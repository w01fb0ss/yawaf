use async_recursion::async_recursion;
use hyper::{Body, Request};
use nom::error::context;
use nom::{IResult, AsBytes};
use nom::sequence::{tuple, delimited};
use nom::character::complete::{multispace1, multispace0};
use crate::rules_parser::rule_directive::RuleDirective;
use crate::rules_parser::rule_variable::{RuleVariableType, RuleVariable};
use crate::rules_parser::{rule_directive, rule_variable, rule_operator, rule_action};
use crate::rules_parser::rule_operator::{RuleOperator};
use crate::rules_parser::rule_action::{RuleAction, RuleActionType};
use hyper::http::uri::PathAndQuery;
use std::net::SocketAddr;
use hyper::header::COOKIE;
use log::log;
use nom::bytes::complete::{tag, take_until};
use nom::combinator::opt;
use crate::rules_parser::rule_action::RuleActionType::Chain;

type RuleChainLink = Option<Box<Rule>>;

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub directive: RuleDirective,
    pub variables: Vec<RuleVariable>,
    pub operator: RuleOperator,
    pub actions: Vec<RuleAction>,
    pub next_in_chain: RuleChainLink,
}

impl Rule {
    pub fn push(&mut self, rule: Rule) {
        let new_link = Box::new(Rule {
            directive: rule.directive,
            variables: rule.variables,
            operator: rule.operator,
            actions: rule.actions,
            next_in_chain: std::mem::replace(&mut self.next_in_chain, None)
        });

        self.next_in_chain = Some(new_link);
    }

    #[async_recursion]
    pub async fn matches(&self, request: Request<Body>) -> (Request<Body>, bool) {
        let (reconstructed_request, raw_values) = self.extract_raw_values(request).await;

        let transformed_values = self.transform(raw_values);

        let matched_current_rule = transformed_values
            .iter()
            .any(|str| self.evaluate_operation(str));

        return match &self.next_in_chain {
            None => { (reconstructed_request, matched_current_rule) }
            Some(next_in_chain) => {
                let (next_reconstructed_req, matches_chain) = next_in_chain.matches(reconstructed_request).await;
                (next_reconstructed_req, matched_current_rule && matches_chain)
            }
        };
    }

    async fn extract_raw_values(&self, mut request: Request<Body>) -> (Request<Body>, Vec<String>) {
        let mut raw_values: Vec<String> = vec![];
        for var in self.variables.clone().iter() {
            let (reconstructed_request, mut extracted_values) = extract_from(request, &var)
                .await;


            request = reconstructed_request;
            raw_values.append(&mut extracted_values);
        }

        return (request, raw_values);
    }

    fn transform(&self, raw_values: Vec<String>) -> Vec<String> {
        let transformed_values;
        if !self.transformations().is_empty() {
            transformed_values = self.apply_transformations(&raw_values);
        } else {
            transformed_values = raw_values;
        }
        transformed_values
    }

    fn apply_transformations(&self, values: &Vec<String>) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();

        let transformation_actions = self.transformations();
        if !transformation_actions.is_empty() {
            for raw_value in values.iter() {
                let mut temp_value = raw_value.clone();
                for transformation in transformation_actions.iter() {
                    temp_value = match transformation.argument.as_ref().unwrap().as_str() {
                        "base64Decode" => String::from_utf8(base64::decode(temp_value).unwrap()).unwrap(),
                        "sqlHexDecode" => unimplemented!("Not implemented yet!"),
                        "base64Encode" => base64::encode(temp_value),
                        "cmdLine" => unimplemented!("Not implemented yet!"),
                        "compressWhitespace" => {
                            let whitespace_pattern = regex::Regex::new(r"\s+").unwrap();
                            whitespace_pattern.replace_all(&*temp_value, " ").to_string()
                        }
                        "removeNulls" => temp_value.replace("\u{0000}", ""),
                        "replaceNulls" => temp_value.replace("\u{0000}", " "),
                        "lowercase" => temp_value.to_lowercase(),
                        "uppercase" => temp_value.to_uppercase(),
                        "urlDecode" => urlencoding::decode(&*temp_value).unwrap().to_string(),
                        "urlEncode" => unimplemented!("Not implemented yet!"),
                        "hexDecode" => unimplemented!("Not implemented yet!"),
                        "hexEncode" => unimplemented!("Not implemented yet!"),
                        "htmlEntityEncode" => html_escape::encode_safe(temp_value.as_str()).to_string(),
                        "htmlEntityDecode" => html_escape::decode_html_entities(temp_value.as_str()).to_string(),
                        _ => temp_value,
                    }
                }
                result.push(temp_value);
            }
        }

        return result;
    }

    fn transformations(&self) -> Vec<RuleAction> {
        self.actions.clone()
            .into_iter()
            .filter(|action| action.action_type == RuleActionType::T)
            .collect::<Vec<RuleAction>>()
    }
}

fn wrap_non_destructive(request: Request<Body>, extraction_operation: fn(&Request<Body>) -> Vec<String>) -> (Request<Body>, Vec<String>) {
    let extracted_values = extraction_operation(&request);
    (request, extracted_values)
}

fn extract_request_uri_raw(request: &Request<Body>) -> Vec<String> {
    vec![request.uri().to_string()]
}

fn extract_request_uri(request: &Request<Body>) -> Vec<String> {
    vec![request.uri().path_and_query()
        .map_or_else(|| "".to_string(), PathAndQuery::to_string)]
}

fn extract_header_names(request: &Request<Body>) -> Vec<String> {
    request.headers()
        .keys()
        .map(|key| key.to_string())
        .collect::<Vec<String>>()
}

fn extract_headers(request: &Request<Body>) -> Vec<String> {
    request.headers()
        .iter()
        .map(|(key, value)| key.to_string() + ": " + value.to_str().unwrap_or(""))
        .collect::<Vec<String>>()
}

fn extract_cookies(request: &Request<Body>) -> Vec<String> {
    request.headers().get(COOKIE)
        .into_iter()
        .map(|header_value| header_value.to_str().unwrap().to_string())
        .collect::<Vec<String>>()
}

fn extract_remote_port(request: &Request<Body>) -> Vec<String> {
    vec![request.extensions().get::<SocketAddr>().unwrap()
        .port().to_string()]
}

fn extract_remote_address(request: &Request<Body>) -> Vec<String> {
    vec![request.extensions().get::<SocketAddr>().unwrap()
        .ip().to_string()]
}

fn extract_args_get(request: &Request<Body>) -> Vec<String> {
    vec![request.uri().query().unwrap_or_else(|| "").to_string()]
}

async fn extract_from(request: Request<Body>, rule_var: &RuleVariable) -> (Request<Body>, Vec<String>) {
    let (reconstructed_request, mut extracted_values) =
        match rule_var.variable_type {
            RuleVariableType::Args => unimplemented!("Not implemented yet!"),
            RuleVariableType::ArgsCombinedSize => unimplemented!("Not implemented yet!"),
            RuleVariableType::ArgsGet => wrap_non_destructive(request, extract_args_get),
            RuleVariableType::ArgsGetNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::ArgsNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::ArgsPost => unimplemented!("Not implemented yet!"),
            RuleVariableType::ArgsPostNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::AuthType => unimplemented!("Not implemented yet!"),
            RuleVariableType::Duration => unimplemented!("Not implemented yet!"),
            RuleVariableType::Env => unimplemented!("Not implemented yet!"),
            RuleVariableType::Files => unimplemented!("Not implemented yet!"),
            RuleVariableType::FilesCombinedSize => unimplemented!("Not implemented yet!"),
            RuleVariableType::FilesNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::FullRequest => unimplemented!("Not implemented yet!"),
            RuleVariableType::FullRequestLength => unimplemented!("Not implemented yet!"),
            RuleVariableType::FilesSizes => unimplemented!("Not implemented yet!"),
            RuleVariableType::FilesTmpnames => unimplemented!("Not implemented yet!"),
            RuleVariableType::FilesTmpContent => unimplemented!("Not implemented yet!"),
            RuleVariableType::Geo => unimplemented!("Not implemented yet!"),
            RuleVariableType::HighestSeverity => unimplemented!("Not implemented yet!"),
            RuleVariableType::InboundDataError => unimplemented!("Not implemented yet!"),
            RuleVariableType::MatchedVar => unimplemented!("Not implemented yet!"),
            RuleVariableType::MatchedVars => unimplemented!("Not implemented yet!"),
            RuleVariableType::MatchedVarName => unimplemented!("Not implemented yet!"),
            RuleVariableType::MatchedVarsNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::ModsecBuild => unimplemented!("Not implemented yet!"),
            RuleVariableType::MultipartCrlfLfLines => unimplemented!("Not implemented yet!"),
            RuleVariableType::MultipartFilename => unimplemented!("Not implemented yet!"),
            RuleVariableType::MultipartName => unimplemented!("Not implemented yet!"),
            RuleVariableType::MultipartStrictError => unimplemented!("Not implemented yet!"),
            RuleVariableType::MultipartUnmatchedBoundary => unimplemented!("Not implemented yet!"),
            RuleVariableType::OutboundDataError => unimplemented!("Not implemented yet!"),
            RuleVariableType::PathInfo => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfAll => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfCombined => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfGc => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfLogging => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfPhase1 => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfPhase2 => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfPhase3 => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfPhase4 => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfPhase5 => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfRules => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfSread => unimplemented!("Not implemented yet!"),
            RuleVariableType::PerfSwrite => unimplemented!("Not implemented yet!"),
            RuleVariableType::QueryString => unimplemented!("Not implemented yet!"),
            RuleVariableType::RemoteAddr => wrap_non_destructive(request, extract_remote_address),
            RuleVariableType::RemoteHost => unimplemented!("Not implemented yet!"),
            RuleVariableType::RemotePort => wrap_non_destructive(request, extract_remote_port),
            RuleVariableType::RemoteUser => unimplemented!("Not implemented yet!"),
            RuleVariableType::ReqbodyError => unimplemented!("Not implemented yet!"),
            RuleVariableType::ReqbodyErrorMsg => unimplemented!("Not implemented yet!"),
            RuleVariableType::ReqbodyProcessor => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestBasename => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestBody => extract_body(request).await,
            RuleVariableType::RequestBodyLength => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestCookies => wrap_non_destructive(request, extract_cookies),
            RuleVariableType::RequestCookiesNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestFilename => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestHeaders => wrap_non_destructive(request, extract_headers),
            RuleVariableType::RequestHeadersNames => wrap_non_destructive(request, extract_header_names),
            RuleVariableType::RequestLine => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestMethod => wrap_non_destructive(request, extract_request_method),
            RuleVariableType::RequestProtocol => unimplemented!("Not implemented yet!"),
            RuleVariableType::RequestUri => wrap_non_destructive(request, extract_request_uri),
            RuleVariableType::RequestUriRaw => wrap_non_destructive(request, extract_request_uri_raw),
            RuleVariableType::ResponseBody => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseContentLength => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseContentType => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseHeaders => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseHeadersNames => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseProtocol => unimplemented!("Not implemented yet!"),
            RuleVariableType::ResponseStatus => unimplemented!("Not implemented yet!"),
            RuleVariableType::Rule => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptBasename => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptFilename => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptGid => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptGroupname => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptMode => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptUid => unimplemented!("Not implemented yet!"),
            RuleVariableType::ScriptUsername => unimplemented!("Not implemented yet!"),
            RuleVariableType::SdbmDeleteError => unimplemented!("Not implemented yet!"),
            RuleVariableType::ServerAddr => unimplemented!("Not implemented yet!"),
            RuleVariableType::ServerName => unimplemented!("Not implemented yet!"),
            RuleVariableType::ServerPort => unimplemented!("Not implemented yet!"),
            RuleVariableType::Session => unimplemented!("Not implemented yet!"),
            RuleVariableType::Sessionid => unimplemented!("Not implemented yet!"),
            RuleVariableType::StatusLine => unimplemented!("Not implemented yet!"),
            RuleVariableType::StreamInputBody => unimplemented!("Not implemented yet!"),
            RuleVariableType::StreamOutputBody => unimplemented!("Not implemented yet!"),
            RuleVariableType::Time => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeDay => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeEpoch => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeHour => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeMin => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeMon => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeSec => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeWday => unimplemented!("Not implemented yet!"),
            RuleVariableType::TimeYear => unimplemented!("Not implemented yet!"),
            RuleVariableType::Tx => unimplemented!("Not implemented yet!"),
            RuleVariableType::UniqueId => unimplemented!("Not implemented yet!"),
            RuleVariableType::UrlencodedError => unimplemented!("Not implemented yet!"),
            RuleVariableType::Userid => unimplemented!("Not implemented yet!"),
            RuleVariableType::UseragentIp => unimplemented!("Not implemented yet!"),
            RuleVariableType::Webappid => unimplemented!("Not implemented yet!"),
            RuleVariableType::WebserverErrorLog => unimplemented!("Not implemented yet!"),
            RuleVariableType::Xml => unimplemented!("Not implemented yet!"),
        };

    // todo: hacky for now, pass a vector with the number in string form until i can
    //  figure out how i should express this for the type system or redesign this
    extracted_values = match rule_var.count {
        true => vec![extracted_values.len().to_string()],
        false => extracted_values,
    };

    return (reconstructed_request, extracted_values);
}

fn extract_request_method(request: &Request<Body>) -> Vec<String> {
    vec![request.method().to_string()]
}

pub fn parse_rules(input: &str) -> Vec<Rule> {
    let input_with_removed_newlines = input.replace("\\\n", " ");
    let mut str = input_with_removed_newlines.as_str();
    let mut rules: Vec<Rule> = Vec::new();
    while !str.is_empty() {
        let parsing_result = tuple((opt(parse_comments), opt(tag("\n")), opt(parse_rule)))(str);
        let (next_str, (_is_comment, _is_newline, rule)) = parsing_result.unwrap();
        if rule.is_some() {
            rules.push(rule.unwrap());
        }
        str = next_str;
    }

    rules.reverse();

    let mut top_level_rules : Vec<Rule> = Vec::new();
    let mut last_rule: Option<Rule> = None;

    for mut rule in rules {
        match last_rule {
            None => { last_rule = Option::from(rule) }
            Some(actual_rule) => {
                let chains_other_rule = rule.actions.iter()
                    .map(|action| action.action_type)
                    .any(|action_type| action_type == Chain);

                if chains_other_rule {
                    rule.push(actual_rule.clone());
                } else {
                    top_level_rules.push(actual_rule.clone());
                }

                last_rule = Option::from(rule);
            }
        }
    }
    top_level_rules.push(last_rule.unwrap());
    top_level_rules.reverse();

    return top_level_rules;
}

pub fn parse_comments(input: &str) -> IResult<&str, &str> {
    let (input, _) = tuple((
        tag("#"),
        take_until("\n"),
        tag("\n")
    ))(input)?;
    Ok((input, ""))
}


pub fn parse_rule(input: &str) -> IResult<&str, Rule> {
    context(
        "rule",
        delimited(
            multispace0,
            tuple((
                rule_directive::parse_directive,
                multispace1,
                rule_variable::parse_variables,
                multispace1,
                rule_operator::parse_operator,
                multispace1,
                rule_action::parse_actions,
            )),
            multispace0,
        ),
    )(input)
        .map(|(next_input, result)| {
            let (
                directive,
                _,
                variables,
                _,
                operator,
                _,
                actions,
            ) = result;
            return (next_input,
                    Rule {
                        directive,
                        variables,
                        operator,
                        actions,
                        next_in_chain: None,
                    }
            );
        })
}

async fn extract_body(request: Request<Body>) -> (Request<Body>, Vec<String>) {
    let (parts, body) = request.into_parts();
    let bytes = hyper::body::to_bytes(body).await.unwrap();
    let bytes_clone = bytes.clone();

    log::debug!("{:?}", bytes);
    log::debug!("{:?}", bytes_clone);

    let body_key_value_tuples: Vec<(String, String)> = serde_urlencoded::from_bytes(bytes.as_bytes()).unwrap();
    let body_params: Vec<String> = body_key_value_tuples.iter()
        .map(|(k, v)| k.to_owned() + "=" + v)
        .collect();
    let reconstructed_body = body_params.join("&");
    return (Request::from_parts(parts, Body::from(bytes_clone)), vec![reconstructed_body]);
}

#[cfg(test)]
mod tests {
    use crate::rules_parser::rule::{parse_rules, Rule, extract_from, parse_rule, extract_body};
    use crate::rules_parser::rule_directive::RuleDirective;
    use crate::rules_parser::rule_action::{RuleAction, RuleActionType};
    use crate::rules_parser::rule_variable::{RuleVariable, RuleVariableType};
    use crate::rules_parser::rule_operator::{RuleOperatorType, RuleOperator};
    use hyper::{Version, Body, Request};
    use std::net::SocketAddr;
    use nom::AsBytes;
    use crate::rules_parser::rule_variable::RuleVariableType::RemoteAddr;

    #[test]
    fn parse_comments() {
        let input = r#"# ------------------------------------------------------------------------
# OWASP ModSecurity Core Rule Set ver.3.3.4
# Copyright (c) 2006-2020 Trustwave and contributors. All rights reserved.
# Copyright (c) 2021-2022 Core Rule Set project. All rights reserved.
#
# The OWASP ModSecurity Core Rule Set is distributed under
# Apache Software License (ASL) version 2
# Please see the enclosed LICENSE file for full details.
# ------------------------------------------------------------------------

#
# This file REQUEST-901-INITIALIZATION.conf initializes the Core Rules
# and performs preparatory actions. It also fixes errors and omissions
# of variable definitions in the file crs-setup.conf.
# The setup.conf can and should be edited by the user, this file
# is part of the CRS installation and should not be altered.
#


#
# -=[ Rules Version ]=-
#
# Rule version data is added to the "Producer" line of Section H of the Audit log:
#
# - Producer: ModSecurity for Apache/2.9.1 (http://www.modsecurity.org/); OWASP_CRS/3.1.0.
#
# Ref: https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual#wiki-SecComponentSignature
#
SecComponentSignature "OWASP_CRS/3.3.4"

#
# -=[ Default setup values ]=-
#
# The CRS checks the tx.crs_setup_version variable to ensure that the setup
# file is included at the correct time. This detects situations where
# necessary settings are not defined, for instance if the file
# inclusion order is incorrect, or if the user has forgotten to
# include the crs-setup.conf file.
#
# If you are upgrading from an earlier version of the CRS and you are
# getting this error, please make a new copy of the setup template
# crs-setup.conf.example to crs-setup.conf, and re-apply your policy
# changes. There have been many changes in settings syntax from CRS2
# to CRS3, so an old setup file may cause unwanted behavior.
#
# If you are not planning to use the crs-setup.conf template, you must
# manually set the tx.crs_setup_version variable before including
# the CRS rules/* files.
#
# The variable is a numerical representation of the CRS version number.
# E.g., v3.0.0 is represented as 300.
#

SecRule &TX:crs_setup_version "@eq 0" \
    "id:901001,\
    phase:1,\
    deny,\
    status:500,\
    log,\
    auditlog,\
    msg:'ModSecurity Core Rule Set is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions',\
    ver:'OWASP_CRS/3.3.4',\
    severity:'CRITICAL'"


#
# -=[ Default setup values ]=-
#
# Some constructs or individual rules will fail if certain parameters
# are not set in the setup.conf file. The following rules will catch
# these cases and assign sane default values.
#

# Default Inbound Anomaly Threshold Level (rule 900110 in setup.conf)
SecRule &TX:inbound_anomaly_score_threshold "@eq 0" \
    "id:901100,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.inbound_anomaly_score_threshold=5'"

# Default Outbound Anomaly Threshold Level (rule 900110 in setup.conf)
SecRule &TX:outbound_anomaly_score_threshold "@eq 0" \
    "id:901110,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.outbound_anomaly_score_threshold=4'"

# Default Paranoia Level (rule 900000 in setup.conf)
SecRule &TX:paranoia_level "@eq 0" \
    "id:901120,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.paranoia_level=1'"

# Default Executing Paranoia Level (rule 900000 in setup.conf)
SecRule &TX:executing_paranoia_level "@eq 0" \
    "id:901125,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.executing_paranoia_level=%{TX.PARANOIA_LEVEL}'"

# Default Sampling Percentage (rule 900400 in setup.conf)
SecRule &TX:sampling_percentage "@eq 0" \
    "id:901130,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.sampling_percentage=100'"

# Default Anomaly Scores (rule 900100 in setup.conf)
SecRule &TX:critical_anomaly_score "@eq 0" \
    "id:901140,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.critical_anomaly_score=5'"

SecRule &TX:error_anomaly_score "@eq 0" \
    "id:901141,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.error_anomaly_score=4'"

SecRule &TX:warning_anomaly_score "@eq 0" \
    "id:901142,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.warning_anomaly_score=3'"

SecRule &TX:notice_anomaly_score "@eq 0" \
    "id:901143,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.notice_anomaly_score=2'"

# Default do_reput_block
SecRule &TX:do_reput_block "@eq 0" \
    "id:901150,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.do_reput_block=0'"

# Default block duration
SecRule &TX:reput_block_duration "@eq 0" \
    "id:901152,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.reput_block_duration=300'"

# Default HTTP policy: allowed_methods (rule 900200)
SecRule &TX:allowed_methods "@eq 0" \
    "id:901160,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS'"

# Default HTTP policy: allowed_request_content_type (rule 900220)
SecRule &TX:allowed_request_content_type "@eq 0" \
    "id:901162,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json|'"

# Default HTTP policy: allowed_request_content_type_charset (rule 900270)
SecRule &TX:allowed_request_content_type_charset "@eq 0" \
    "id:901168,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.allowed_request_content_type_charset=utf-8|iso-8859-1|iso-8859-15|windows-1252'"

# Default HTTP policy: allowed_http_versions (rule 900230)
SecRule &TX:allowed_http_versions "@eq 0" \
    "id:901163,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.allowed_http_versions=HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0'"

# Default HTTP policy: restricted_extensions (rule 900240)
SecRule &TX:restricted_extensions "@eq 0" \
    "id:901164,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.restricted_extensions=.asa/ .asax/ .ascx/ .axd/ .backup/ .bak/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .com/ .config/ .conf/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dll/ .dos/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .ini/ .key/ .licx/ .lnk/ .log/ .mdb/ .old/ .pass/ .pdb/ .pol/ .printer/ .pwd/ .rdb/ .resources/ .resx/ .sql/ .swp/ .sys/ .vb/ .vbs/ .vbproj/ .vsdisco/ .webinfo/ .xsd/ .xsx/'"

# Default HTTP policy: restricted_headers (rule 900250)
SecRule &TX:restricted_headers "@eq 0" \
    "id:901165,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.restricted_headers=/accept-charset/ /content-encoding/ /proxy/ /lock-token/ /content-range/ /if/'"

# Default HTTP policy: static_extensions (rule 900260)
SecRule &TX:static_extensions "@eq 0" \
    "id:901166,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.static_extensions=/.jpg/ /.jpeg/ /.png/ /.gif/ /.js/ /.css/ /.ico/ /.svg/ /.webp/'"

# Default enforcing of body processor URLENCODED
SecRule &TX:enforce_bodyproc_urlencoded "@eq 0" \
    "id:901167,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.enforce_bodyproc_urlencoded=0'"

#
# -=[ Initialize internal variables ]=-
#

# Initialize anomaly scoring variables.
# All _score variables start at 0, and are incremented by the various rules
# upon detection of a possible attack.
# sql_error_match is used for shortcutting rules for performance reasons.

SecAction \
    "id:901200,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.anomaly_score=0',\
    setvar:'tx.anomaly_score_pl1=0',\
    setvar:'tx.anomaly_score_pl2=0',\
    setvar:'tx.anomaly_score_pl3=0',\
    setvar:'tx.anomaly_score_pl4=0',\
    setvar:'tx.sql_injection_score=0',\
    setvar:'tx.xss_score=0',\
    setvar:'tx.rfi_score=0',\
    setvar:'tx.lfi_score=0',\
    setvar:'tx.rce_score=0',\
    setvar:'tx.php_injection_score=0',\
    setvar:'tx.http_violation_score=0',\
    setvar:'tx.session_fixation_score=0',\
    setvar:'tx.inbound_anomaly_score=0',\
    setvar:'tx.outbound_anomaly_score=0',\
    setvar:'tx.outbound_anomaly_score_pl1=0',\
    setvar:'tx.outbound_anomaly_score_pl2=0',\
    setvar:'tx.outbound_anomaly_score_pl3=0',\
    setvar:'tx.outbound_anomaly_score_pl4=0',\
    setvar:'tx.sql_error_match=0'"


#
# -=[ Initialize collections ]=-
#
# Create both Global and IP collections for rules to use.
# There are some CRS rules that assume that these two collections
# have already been initiated.
#

SecRule REQUEST_HEADERS:User-Agent "@rx ^.*$" \
    "id:901318,\
    phase:1,\
    pass,\
    t:none,t:sha1,t:hexEncode,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'tx.ua_hash=%{MATCHED_VAR}'"

SecAction \
    "id:901321,\
    phase:1,\
    pass,\
    t:none,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    initcol:global=global,\
    initcol:ip=%{remote_addr}_%{tx.ua_hash},\
    setvar:'tx.real_ip=%{remote_addr}'"

#
# -=[ Initialize Correct Body Processing ]=-
#
# Force request body variable and optionally request body processor
#

# Force body variable
SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
    "id:901340,\
    phase:1,\
    pass,\
    nolog,\
    noauditlog,\
    msg:'Enabling body inspection',\
    tag:'paranoia-level/1',\
    ctl:forceRequestBodyVariable=On,\
    ver:'OWASP_CRS/3.3.4'"

# Force body processor URLENCODED
SecRule TX:enforce_bodyproc_urlencoded "@eq 1" \
    "id:901350,\
    phase:1,\
    pass,\
    t:none,t:urlDecodeUni,\
    nolog,\
    noauditlog,\
    msg:'Enabling forced body inspection for ASCII content',\
    ver:'OWASP_CRS/3.3.4',\
    chain"
    SecRule REQBODY_PROCESSOR "!@rx (?:URLENCODED|MULTIPART|XML|JSON)" \
        "ctl:requestBodyProcessor=URLENCODED"


#
# -=[ Easing In / Sampling Percentage ]=-
#
# This is used to send only a limited percentage of requests into the Core
# Rule Set. The selection is based on TX.sampling_percentage and a pseudo
# random number calculated below.
#
# Use this to ease into a new Core Rules installation with an existing
# productive service.
#
# See
# https://www.netnea.com/cms/2016/04/26/easing-in-conditional-modsecurity-rule-execution-based-on-pseudo-random-numbers/
#

#
# Generate the pseudo random number
#
# ATTENTION: This is no cryptographically secure random number. It's just
# a cheap way to get some random number suitable for sampling.
#
# We take the entropy contained in the UNIQUE_ID. We hash that variable and
# take the first integer numbers out of it. Theoretically, it is possible
# there are no integers in a sha1 hash. We make sure we get two
# integer numbers by taking the last two digits from the DURATION counter
# (in microseconds).
# Finally, leading zeros are removed from the two-digit random number.
#

SecRule TX:sampling_percentage "@eq 100" \
    "id:901400,\
    phase:1,\
    pass,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    skipAfter:END-SAMPLING"

SecRule UNIQUE_ID "@rx ^." \
    "id:901410,\
    phase:1,\
    pass,\
    t:sha1,t:hexEncode,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'TX.sampling_rnd100=%{MATCHED_VAR}'"

SecRule DURATION "@rx (..)$" \
    "id:901420,\
    phase:1,\
    pass,\
    capture,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'TX.sampling_rnd100=%{TX.sampling_rnd100}%{TX.1}'"

SecRule TX:sampling_rnd100 "@rx ^[a-f]*([0-9])[a-f]*([0-9])" \
    "id:901430,\
    phase:1,\
    pass,\
    capture,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'TX.sampling_rnd100=%{TX.1}%{TX.2}'"

SecRule TX:sampling_rnd100 "@rx ^0([0-9])" \
    "id:901440,\
    phase:1,\
    pass,\
    capture,\
    nolog,\
    ver:'OWASP_CRS/3.3.4',\
    setvar:'TX.sampling_rnd100=%{TX.1}'"


#
# Sampling decision
#
# If a request is allowed to pass without being checked by the CRS, there is no
# entry in the audit log (for performance reasons), but an error log entry is
# being written.  If you want to disable the error log entry, then issue the
# following directive somewhere after the inclusion of the CRS
# (E.g., RESPONSE-999-EXCEPTIONS.conf).
#
# SecRuleUpdateActionById 901450 "nolog"
#


SecRule TX:sampling_rnd100 "!@lt %{tx.sampling_percentage}" \
    "id:901450,\
    phase:1,\
    pass,\
    log,\
    noauditlog,\
    msg:'Sampling: Disable the rule engine based on sampling_percentage %{TX.sampling_percentage} and random number %{TX.sampling_rnd100}',\
    ctl:ruleEngine=Off,\
    ver:'OWASP_CRS/3.3.4'"

SecMarker "END-SAMPLING"


#
# Configuration Plausibility Checks
#

# Make sure executing paranoia level is not lower than paranoia level
SecRule TX:executing_paranoia_level "@lt %{tx.paranoia_level}" \
    "id:901500,\
    phase:1,\
    deny,\
    status:500,\
    t:none,\
    log,\
    msg:'Executing paranoia level configured is lower than the paranoia level itself. This is illegal. Blocking request. Aborting',\
    ver:'OWASP_CRS/3.3.4'"
"#;
    }

    #[test]
    fn parse_rules_should_parse_multiple_rules_completely() {
        let rules = parse_rules(r###"
    SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" \
        "id:102,phase:1,t:none,nolog,pass,ctl:ruleEngine=off"

    SecRule REQUEST_URI "@beginsWith /index.php/component/users/" \
        "id:5,phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=981318"
"###);

        assert_eq!(vec![
            Rule {
                directive: RuleDirective::SecRule,
                variables: vec![
                    RuleVariable {
                        count: false,
                        variable_type: RuleVariableType::RemoteAddr,
                    }
                ],
                operator: RuleOperator {
                    negated: false,
                    operator_type: RuleOperatorType::IpMatch,
                    argument: "192.168.1.101".to_string(),
                },
                actions: vec![
                    RuleAction {
                        action_type: RuleActionType::Id,
                        argument: Some("102".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::Phase,
                        argument: Some("1".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::T,
                        argument: Some("none".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::Nolog,
                        argument: None,
                    },
                    RuleAction {
                        action_type: RuleActionType::Pass,
                        argument: None,
                    },
                    RuleAction {
                        action_type: RuleActionType::Ctl,
                        argument: Some("ruleEngine=off".to_string()),
                    },
                ],
                next_in_chain: None,
            },
            Rule {
                directive: RuleDirective::SecRule,
                variables: vec![RuleVariable {
                    count: false,
                    variable_type: RuleVariableType::RequestUri,
                }],
                operator: RuleOperator {
                    negated: false,
                    operator_type: RuleOperatorType::BeginsWith,
                    argument: "/index.php/component/users/".to_string(),
                },
                actions: vec![
                    RuleAction {
                        action_type: RuleActionType::Id,
                        argument: Some("5".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::Phase,
                        argument: Some("1".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::T,
                        argument: Some("none".to_string()),
                    },
                    RuleAction {
                        action_type: RuleActionType::Pass,
                        argument: None,
                    },
                    RuleAction {
                        action_type: RuleActionType::Nolog,
                        argument: None,
                    },
                    RuleAction {
                        action_type: RuleActionType::Ctl,
                        argument: Some("ruleRemoveTargetById=981318".to_string()),
                    },
                ],
                next_in_chain: None,
            }
        ], rules);
    }

    #[test]
    fn should_push_rules_in_chain() {
        let mut rule1 = Rule {
            directive: RuleDirective::SecAction,
            variables: vec![],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::BeginsWith,
                argument: "".to_string()
            },
            actions: vec![],
            next_in_chain: None
        };

        let mut rule2 = Rule {
            directive: RuleDirective::SecAction,
            variables: vec![],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::EndsWith,
                argument: "".to_string()
            },
            actions: vec![],
            next_in_chain: None
        };

        let rule3 = Rule {
            directive: RuleDirective::SecAction,
            variables: vec![],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::IpMatch,
                argument: "".to_string()
            },
            actions: vec![],
            next_in_chain: None
        };


        rule2.push(rule3);
        rule1.push(rule2);

        log::debug!("{:?}", rule1);
    }

    #[test]
    fn parse_rules_should_handle_chains() {
        let rules = parse_rules(r###"
    SecRule REMOTE_ADDR "@ipMatch 192.168.1.101" \
        "chain"
        SecRule REQUEST_METHOD "@eq POST" \
            "block"

    SecRule REQUEST_URI "@beginsWith /index.php/component/users/" \
        "block"
"###);

        assert_eq!(vec![Rule {
            directive: RuleDirective::SecRule,
            variables: vec![RuleVariable {
                count: false,
                variable_type: RuleVariableType::RemoteAddr,
            }],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::IpMatch,
                argument: "192.168.1.101".to_string(),
            },
            actions: vec![RuleAction { action_type: RuleActionType::Chain, argument: None }],
            next_in_chain: Some(Box::new(
                Rule {
                    directive: RuleDirective::SecRule,
                    variables: vec![RuleVariable {
                        count: false,
                        variable_type: RuleVariableType::RequestMethod,
                    }],
                    operator: RuleOperator {
                        negated: false,
                        operator_type: RuleOperatorType::Equals,
                        argument: "POST".to_string(),
                    },
                    actions: vec![RuleAction { action_type: RuleActionType::Block, argument: None }],
                    next_in_chain: None,
                }
            )),
        }, Rule {
            directive: RuleDirective::SecRule,
            variables: vec![RuleVariable {
                count: false,
                variable_type: RuleVariableType::RequestUri,
            }],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::BeginsWith,
                argument: "/index.php/component/users/".to_string(),
            },
            actions: vec![RuleAction { action_type: RuleActionType::Block, argument: None }],
            next_in_chain: None,
        }], rules)
    }

    #[tokio::test]
    async fn extract_variables_should_extract_headers() {
        let mut request = Request::builder()
            .method("POST")
            .header("abcd", "qwerty")
            .header("ader", "<script>alert(1);</script>")
            .body(Body::empty())
            .unwrap();
        let rule = Rule {
            directive: RuleDirective::SecRule,
            variables: vec![RuleVariable {
                count: false,
                variable_type: RuleVariableType::RequestHeaders,
            }],
            operator: RuleOperator {
                negated: false,
                operator_type: RuleOperatorType::DetectXSS,
                argument: "".to_string(),
            },
            actions: vec![],
            next_in_chain: None,
        };

        let extracted_values = extract_from(request, &rule.variables[0]).await.1;
        log::debug!("{:?}", extracted_values);
        assert!(!extracted_values.is_empty());
    }

    #[test]
    fn parse_rule_should_extract_basic_elements() {
        let raw_rule = r###"SecRule REQUEST_FILENAME "@endsWith /admin/config/development/maintenance" \
        "id:9001128,\
        phase:2,\
        pass,\
        nolog,\
        ctl:ruleRemoveById=942440,\
        ver:'OWASP_CRS/3.3.0'"
    "###.replace("\\\n", " ").to_owned();

        assert_eq!(parse_rule(&*raw_rule).unwrap().1,
                   Rule {
                       directive: RuleDirective::SecRule,
                       variables: vec![RuleVariable {
                           count: false,
                           variable_type: RuleVariableType::RequestFilename,
                       }],
                       operator: RuleOperator {
                           negated: false,
                           operator_type: RuleOperatorType::EndsWith,
                           argument: "/admin/config/development/maintenance".to_string(),
                       },
                       actions: vec![
                           RuleAction {
                               action_type: RuleActionType::Id,
                               argument: Some("9001128".to_string()),
                           },
                           RuleAction {
                               action_type: RuleActionType::Phase,
                               argument: Some("2".to_string()),
                           },
                           RuleAction {
                               action_type: RuleActionType::Pass,
                               argument: None,
                           },
                           RuleAction {
                               action_type: RuleActionType::Nolog,
                               argument: None,
                           },
                           RuleAction {
                               action_type: RuleActionType::Ctl,
                               argument: Some("ruleRemoveById=942440".to_string()),
                           },
                           RuleAction {
                               action_type: RuleActionType::Ver,
                               argument: Some("'OWASP_CRS/3.3.0'".to_string()),
                           },
                       ],
                       next_in_chain: None,
                   }
        );
    }

    #[tokio::test]
    async fn extract_body_should_return_a_new_request() {
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Host", "localhost")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.5")
            .header("Accept-Encoding", "gzip, deflate")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", " 32")
            .header("Origin", "http://localhost")
            .header("Referer", "http://localhost/vulnerabilities/exec/")
            .extension(SocketAddr::from(([192, 168, 0, 1], 12000)))
            .body(Body::from("ip=%3B+ls+-alh+%2F&Submit=Submit"))
            .unwrap();


        let (request_for_origin, body) = extract_body(request).await;
        assert_eq!("/", request_for_origin.uri());
        assert_eq!(8, request_for_origin.headers().len());
        let forwarded_body = hyper::body::to_bytes(request_for_origin.into_body()).await.unwrap();
        assert_eq!("ip=%3B+ls+-alh+%2F&Submit=Submit".to_string(),
                   String::from_utf8(forwarded_body.as_bytes().to_vec()).unwrap());
    }

    #[tokio::test]
    async fn extract_from_should_extract_request_body() {
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Host", "localhost")
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
            .header("Accept-Language", " en-US,en;q=0.5")
            .header("Accept-Encoding", " gzip, deflate")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Content-Length", "32")
            .header("Origin", " http://localhost")
            .header("Referer", " http://localhost/some/path/url")
            .extension(SocketAddr::from(([192, 168, 0, 1], 12000)))
            .body(Body::from("ip=%3B+ls+-alh+%2F&Submit=Submit"))
            .unwrap();

        let (request_for_origin, vec) = extract_from(request, &RuleVariable {
            count: false,
            variable_type: RuleVariableType::RequestBody,
        }).await;

        assert_eq!(vec!["ip=; ls -alh /&Submit=Submit"], vec);
        assert_eq!(request_for_origin.version(), Version::HTTP_11);
        let forwarded_body = hyper::body::to_bytes(request_for_origin.into_body()).await.unwrap();
        assert_eq!("ip=%3B+ls+-alh+%2F&Submit=Submit".to_string(),
                   String::from_utf8(forwarded_body.as_bytes().to_vec()).unwrap());
    }
}