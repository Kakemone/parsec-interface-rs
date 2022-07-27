// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::generated_ops::attest_key::{
    attestation_mechanism_params, attestation_output, AttestationMechanismParams,
    AttestationOutput, Operation as OperationProto, Result as ResultProto,
};
use crate::operations::attest_key::{Operation, Result};
use crate::requests::ResponseStatus;
use log::error;
use std::convert::TryFrom;

impl TryFrom<Operation> for OperationProto {
    type Error = ResponseStatus;

    fn try_from(op: Operation) -> std::result::Result<Self, Self::Error> {
        match op {
            Operation::ActivateCredential {
                attested_key_name,
                attesting_key_name,
                credential_blob,
                secret,
            } => Ok(OperationProto {
                attested_key_name,
                attesting_key_name: attesting_key_name.unwrap_or_default(),
                parameters: Some(AttestationMechanismParams {
                    mechanism: Some(attestation_mechanism_params::Mechanism::ActivateCredential(
                        attestation_mechanism_params::ActivateCredential {
                            credential_blob: credential_blob.to_vec(),
                            secret: secret.to_vec(),
                        },
                    )),
                }),
            }),
            Operation::CertifyAndQuote {
                attested_key_name,
                nonce,
                attesting_key_name,
            } => Ok(OperationProto {
                attested_key_name,
                attesting_key_name: attesting_key_name.unwrap_or_default(),
                parameters: Some(AttestationMechanismParams {
                    mechanism: Some(attestation_mechanism_params::Mechanism::CertifyAndQuote(
                        attestation_mechanism_params::CertifyAndQuote {
                            nonce: nonce.to_vec(),
                        },
                    )),
                }),
            }),
        }
    }
}

impl TryFrom<OperationProto> for Operation {
    type Error = ResponseStatus;

    fn try_from(proto_op: OperationProto) -> std::result::Result<Self, Self::Error> {
        match proto_op.parameters {
            Some(AttestationMechanismParams {
                mechanism:
                    Some(attestation_mechanism_params::Mechanism::ActivateCredential(
                        attestation_mechanism_params::ActivateCredential {
                            credential_blob,
                            secret,
                        },
                    )),
            }) => Ok(Operation::ActivateCredential {
                attested_key_name: proto_op.attested_key_name,
                attesting_key_name: if proto_op.attesting_key_name.is_empty() {
                    None
                } else {
                    Some(proto_op.attesting_key_name)
                },
                credential_blob: credential_blob.into(),
                secret: secret.into(),
            }),
            Some(AttestationMechanismParams {
                mechanism:
                    Some(attestation_mechanism_params::Mechanism::CertifyAndQuote(
                        attestation_mechanism_params::CertifyAndQuote {
                            nonce,
                        },
                    )),
            }) => Ok(Operation::CertifyAndQuote {
                attested_key_name: proto_op.attested_key_name,
                attesting_key_name: if proto_op.attesting_key_name.is_empty() {
                    None
                } else {
                    Some(proto_op.attesting_key_name)
                },
                nonce: nonce.into(),
            }),
            _ => {
                error!("The encoding of the operation does not follow the expected pattern");
                Err(ResponseStatus::InvalidEncoding)
            }
        }
    }
}

impl TryFrom<Result> for ResultProto {
    type Error = ResponseStatus;

    fn try_from(op: Result) -> std::result::Result<Self, Self::Error> {
        match op {
            Result::ActivateCredential { credential } => Ok(ResultProto {
                output: Some(AttestationOutput {
                    mechanism: Some(attestation_output::Mechanism::ActivateCredential(
                        attestation_output::ActivateCredential {
                            credential: credential.to_vec(),
                        },
                    )),
                }),
            }),
            Result::CertifyAndQuote { key_attestation_certificate, platform_attestation_certificate } => Ok(ResultProto {
                output: Some(AttestationOutput {
                    mechanism: Some(attestation_output::Mechanism::CertifyAndQuote(
                        attestation_output::CertifyAndQuote {
                            key_attestation_certificate: key_attestation_certificate.to_vec(),
                            platform_attestation_certificate: platform_attestation_certificate.to_vec(),
                        },
                    )),
                }),
            }),
        }
    }
}

impl TryFrom<ResultProto> for Result {
    type Error = ResponseStatus;

    fn try_from(proto_op: ResultProto) -> std::result::Result<Self, Self::Error> {
        match proto_op {
            ResultProto {
                output:
                    Some(AttestationOutput {
                        mechanism:
                            Some(attestation_output::Mechanism::ActivateCredential(
                                attestation_output::ActivateCredential { credential },
                            )),
                    }),
            } => Ok(Result::ActivateCredential {
                credential: credential.into(),
            }),
            ResultProto {
                output: 
                    Some(AttestationOutput {
                        mechanism:
                            Some(attestation_output::Mechanism::CertifyAndQuote(
                                attestation_output::CertifyAndQuote { key_attestation_certificate, platform_attestation_certificate},
                            )),
                    }),
            } => Ok(Result::CertifyAndQuote {
                key_attestation_certificate: key_attestation_certificate.into(),
                platform_attestation_certificate: platform_attestation_certificate.into(),
            }),
            _ => {
                error!("The encoding of the result does not follow the expected pattern");
                Err(ResponseStatus::InvalidEncoding)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::generated_ops::attest_key::{
        attestation_mechanism_params, attestation_output, AttestationMechanismParams,
        AttestationOutput, Operation as OperationProto, Result as ResultProto,
    };
    use super::super::{Convert, ProtobufConverter};
    use crate::operations::{
        attest_key::Operation, attest_key::Result, NativeOperation, NativeResult,
    };
    use crate::requests::Opcode;
    use std::convert::TryInto;

    static CONVERTER: ProtobufConverter = ProtobufConverter {};

    #[test]
    fn attest_key_op_from_proto_certify_and_quote() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");
        let op_nonce = vec![0x88; 8];

        let proto = OperationProto {
            attested_key_name: op_attested_key_name.clone(),
            attesting_key_name: op_attesting_key_name.clone(),
            parameters: Some(AttestationMechanismParams {
                mechanism: Some(attestation_mechanism_params::Mechanism::CertifyAndQuote(
                    attestation_mechanism_params::CertifyAndQuote {
                        nonce: op_nonce.clone(),
                    },
                )),
            }),
        };

        let op: Operation = proto.try_into().expect("Failed conversion");
        if let Operation::CertifyAndQuote {
            attested_key_name,
            attesting_key_name,
            nonce,
        } = op {
            assert_eq!(attested_key_name, op_attested_key_name);
            assert_eq!(
                attesting_key_name.unwrap_or_default(),
                op_attesting_key_name
            );
            assert_eq!(nonce.to_vec(), op_nonce);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_op_from_proto_activate_credential() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");
        let op_credential_blob = vec![0xaa; 32];
        let op_secret = vec![0x11; 16];

        let proto = OperationProto {
            attested_key_name: op_attested_key_name.clone(),
            attesting_key_name: op_attesting_key_name.clone(),
            parameters: Some(AttestationMechanismParams {
                mechanism: Some(attestation_mechanism_params::Mechanism::ActivateCredential(
                    attestation_mechanism_params::ActivateCredential {
                        credential_blob: op_credential_blob.clone(),
                        secret: op_secret.clone(),
                    },
                )),
            }),
        };

        let op: Operation = proto.try_into().expect("Failed conversion");
        if let Operation::ActivateCredential {
            attested_key_name,
            attesting_key_name,
            credential_blob,
            secret,
        } = op {
            assert_eq!(attested_key_name, op_attested_key_name);
            assert_eq!(
                attesting_key_name.unwrap_or_default(),
                op_attesting_key_name
            );
            assert_eq!(credential_blob.to_vec(), op_credential_blob);
            assert_eq!(secret.to_vec(), op_secret);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_proto_no_attesting_certify_and_quote() {
        let op_attested_key_name = String::from("attested key name");
        let op_nonce = vec![0x88; 8];

        let proto = OperationProto {
            attested_key_name: op_attested_key_name,
            attesting_key_name: String::new(),
            parameters: Some(AttestationMechanismParams {
                mechanism: Some(attestation_mechanism_params::Mechanism::CertifyAndQuote(
                    attestation_mechanism_params::CertifyAndQuote {
                        nonce: op_nonce,
                    },
                )),
            }),
        };

        let op: Operation = proto.try_into().expect("Failed conversion");
        if let Operation::CertifyAndQuote {
            attesting_key_name, ..
        } = op {
            assert!(attesting_key_name.is_none());
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_proto_no_attesting_activate_credential() {
        let op_attested_key_name = String::from("attested key name");
        let op_credential_blob = vec![0xaa; 32];
        let op_secret = vec![0x11; 16];
        
        let proto = OperationProto {
            attested_key_name: op_attested_key_name,
            attesting_key_name: String::new(),
            parameters: Some(AttestationMechanismParams {
                mechanism: Some(attestation_mechanism_params::Mechanism::ActivateCredential(
                    attestation_mechanism_params::ActivateCredential {
                        credential_blob: op_credential_blob,
                        secret: op_secret,
                    },
                )),
            }),
        };

        let op: Operation = proto.try_into().expect("Failed conversion");
        if let Operation::ActivateCredential {
            attesting_key_name, ..
        } = op {
            assert!(attesting_key_name.is_none());
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_proto_from_op_certify_and_quote() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");
        let op_nonce = vec![0x88; 8];

        let op = Operation::CertifyAndQuote {
            attested_key_name: op_attested_key_name.clone(),
            attesting_key_name: Some(op_attesting_key_name.clone()),
            nonce: op_nonce.clone().into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed conversion");
        if let OperationProto {
            attested_key_name,
            attesting_key_name,
            parameters:
                Some(AttestationMechanismParams {
                    mechanism:
                        Some(attestation_mechanism_params::Mechanism::CertifyAndQuote(
                            attestation_mechanism_params::CertifyAndQuote {
                                nonce,
                            },
                        )),
                }),
        } = proto
        {
            assert_eq!(attested_key_name, op_attested_key_name);
            assert_eq!(attesting_key_name, op_attesting_key_name);
            assert_eq!(nonce, op_nonce);
        }
    }

    #[test]
    fn attest_key_proto_from_op_activate_credential() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");
        let op_credential_blob = vec![0xaa; 32];
        let op_secret = vec![0x11; 16];

        let op = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name.clone(),
            attesting_key_name: Some(op_attesting_key_name.clone()),
            credential_blob: op_credential_blob.clone().into(),
            secret: op_secret.clone().into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed conversion");
        if let OperationProto {
            attested_key_name,
            attesting_key_name,
            parameters:
                Some(AttestationMechanismParams {
                    mechanism:
                        Some(attestation_mechanism_params::Mechanism::ActivateCredential(
                            attestation_mechanism_params::ActivateCredential {
                                credential_blob,
                                secret,
                            },
                        )),
                }),
        } = proto
        {
            assert_eq!(attested_key_name, op_attested_key_name);
            assert_eq!(attesting_key_name, op_attesting_key_name);
            assert_eq!(credential_blob, op_credential_blob);
            assert_eq!(secret, op_secret);
        }
    }

    #[test]
    fn attest_key_op_no_attesting_certify_and_quote() {
        let op_attested_key_name = String::from("attested key name");
        let op_nonce = vec![0x88; 8];

        let op = Operation::CertifyAndQuote {
            attested_key_name: op_attested_key_name,
            attesting_key_name: None,
            nonce: op_nonce.into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed conversion");
        assert_eq!(proto.attesting_key_name, String::new());
    }

    #[test]
    fn attest_key_op_no_attesting_activate_credential() {
        let op_attested_key_name = String::from("attested key name");
        let op_credential_blob = vec![0xaa; 32];
        let op_secret = vec![0x11; 16];

        let op = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name,
            attesting_key_name: None,
            credential_blob: op_credential_blob.into(),
            secret: op_secret.into(),
        };

        let proto: OperationProto = op.try_into().expect("Failed conversion");
        assert_eq!(proto.attesting_key_name, String::new());
    }

    #[test]
    fn attest_key_op_e2e_certify_and_quote() {
        let op_attested_key_name = String::from("attested key name");
        let op_attesting_key_name = String::from("attesting key name");
        let op_nonce = vec![0x88; 8];

        let op = Operation::CertifyAndQuote {
            attested_key_name: op_attested_key_name,
            attesting_key_name: Some(op_attesting_key_name),
            nonce: op_nonce.into(),
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::AttestKey(op))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_operation(body, Opcode::AttestKey)
            .expect("Failed to convert to operation");
        }

        #[test]
        fn attest_key_op_e2e_activate_credential() {
            let op_attested_key_name = String::from("attested key name");
            let op_attesting_key_name = String::from("attesting key name");
            let op_credential_blob = vec![0xaa; 32];
            let op_secret = vec![0x11; 16];

        let op = Operation::ActivateCredential {
            attested_key_name: op_attested_key_name,
            attesting_key_name: Some(op_attesting_key_name),
            credential_blob: op_credential_blob.into(),
            secret: op_secret.into(),
        };

        let body = CONVERTER
            .operation_to_body(NativeOperation::AttestKey(op))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_operation(body, Opcode::AttestKey)
            .expect("Failed to convert to operation");
    }

    #[test]
    fn attest_key_resp_from_proto_certify_and_quote() {
        let resp_key_attestation_certificate = vec![0x99; 32];
        let resp_platform_attestation_certificate = vec![0xcc; 32];

        let proto = ResultProto {
            output: Some(AttestationOutput {
                mechanism: Some(attestation_output::Mechanism::CertifyAndQuote(
                    attestation_output::CertifyAndQuote {
                        key_attestation_certificate: resp_key_attestation_certificate.clone(),
                        platform_attestation_certificate: resp_platform_attestation_certificate.clone(),
                    },
                )),
            }),
        };

        let resp: Result = proto.try_into().expect("Failed conversion");

        if let Result::CertifyAndQuote { key_attestation_certificate, platform_attestation_certificate } = resp {
            assert_eq!(key_attestation_certificate.to_vec(), resp_key_attestation_certificate);
            assert_eq!(platform_attestation_certificate.to_vec(), resp_platform_attestation_certificate);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_resp_from_proto_activate_credential() {
        let resp_credential = vec![0xbb; 32];

        let proto = ResultProto {
            output: Some(AttestationOutput {
                mechanism: Some(attestation_output::Mechanism::ActivateCredential(
                    attestation_output::ActivateCredential {
                        credential: resp_credential.clone(),
                    },
                )),
            }),
        };

        let resp: Result = proto.try_into().expect("Failed conversion");

        if let Result::ActivateCredential { credential } = resp {
            assert_eq!(credential.to_vec(), resp_credential);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_resp_to_proto_certify_and_quote() {
        let resp_key_attestation_certificate = vec![0x99; 32];
        let resp_platform_attestation_certificate = vec![0xcc; 32];

        let resp = Result::CertifyAndQuote {
            key_attestation_certificate: resp_key_attestation_certificate.clone().into(),
            platform_attestation_certificate: resp_platform_attestation_certificate.clone().into(),
        };

        let proto: ResultProto = resp.try_into().expect("Failed conversion");

        if let ResultProto {
            output:
                Some(AttestationOutput {
                    mechanism:
                        Some(attestation_output::Mechanism::CertifyAndQuote(
                            attestation_output::CertifyAndQuote { key_attestation_certificate, platform_attestation_certificate },
                        )),
                }),
        } = proto
        {
            assert_eq!(key_attestation_certificate.to_vec(), resp_key_attestation_certificate);
            assert_eq!(platform_attestation_certificate.to_vec(), resp_platform_attestation_certificate);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_resp_to_proto_activate_credential() {
        let resp_credential = vec![0xbb; 32];

        let resp = Result::ActivateCredential {
            credential: resp_credential.clone().into(),
        };

        let proto: ResultProto = resp.try_into().expect("Failed conversion");

        if let ResultProto {
            output:
                Some(AttestationOutput {
                    mechanism:
                        Some(attestation_output::Mechanism::ActivateCredential(
                            attestation_output::ActivateCredential { credential },
                        )),
                }),
        } = proto
        {
            assert_eq!(credential.to_vec(), resp_credential);
        } else {
            panic!("`if let` branch not taken")
        }
    }

    #[test]
    fn attest_key_resp_e2e_certify_and_quote() {
        let resp_key_attestation_certificate = vec![0x99; 32];
        let resp_platform_attestation_certificate = vec![0xcc; 32];

        let resp = Result::CertifyAndQuote {
            key_attestation_certificate: resp_key_attestation_certificate.into(),
            platform_attestation_certificate: resp_platform_attestation_certificate.into(),
        };

        let body = CONVERTER
            .result_to_body(NativeResult::AttestKey(resp))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_result(body, Opcode::AttestKey)
            .expect("Failed to convert to operation");
    }

    #[test]
    fn attest_key_resp_e2e_activate_credential() {
        let resp_credential = vec![0xbb; 32];

        let resp = Result::ActivateCredential {
            credential: resp_credential.into(),
        };

        let body = CONVERTER
            .result_to_body(NativeResult::AttestKey(resp))
            .expect("Failed to convert to body");

        let _ = CONVERTER
            .body_to_result(body, Opcode::AttestKey)
            .expect("Failed to convert to operation");
    }
}
