use super::*;

fn request() -> ExchangeRequest {
    let csr = "synthetic-csr-bytes-issuer-validates-pem";
    ExchangeRequest {
        binding: RequestBinding {
            operation: Operation::Redeem,
            request_id: "01".repeat(32),
            profile_sha256: "02".repeat(32),
            csr_sha256: hex::encode(Sha256::digest(csr)),
            predecessor_sha256: None,
        },
        purpose: ProofPurpose::Authorize,
        csr_pem: csr.into(),
        predecessor_certificate_pem: None,
        invitation: Some("03".repeat(32)),
        signature: "04".repeat(64),
    }
}

fn frame(value: &serde_json::Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(value).unwrap();
    let mut frame = (bytes.len() as u32).to_be_bytes().to_vec();
    frame.extend(bytes);
    frame
}

#[tokio::test]
async fn exchange_round_trip_preserves_bound_request_and_rejects_csr_substitution() {
    let mut request = request();
    let mut bytes = Vec::new();
    write_request(&mut bytes, &request).await.unwrap();
    let decoded = read_request(&mut bytes.as_slice()).await.unwrap();
    assert_eq!(decoded.binding, request.binding);
    assert_eq!(decoded.proof_signature().unwrap(), [4; 64]);
    assert_eq!(decoded.invitation, request.invitation);
    request.csr_pem.push_str("substitution");
    let mut output = Vec::new();
    assert!(write_request(&mut output, &request).await.is_err());
    assert!(output.is_empty());
}

#[tokio::test]
async fn missing_credential_wrong_purpose_and_extra_secrets_are_not_accepted() {
    let mut r = request();
    r.invitation = None;
    assert!(r.validate().is_err());
    r.purpose = ProofPurpose::Receipt;
    assert!(r.validate().is_ok());
    r.invitation = Some("03".repeat(32));
    assert!(r.validate().is_err());
    r.invitation = None;
    r.purpose = ProofPurpose::Authorize;
    r.binding.operation = Operation::Renew;
    r.binding.predecessor_sha256 = Some("05".repeat(32));
    assert!(r.validate().is_err());
    r.predecessor_certificate_pem = Some("synthetic-predecessor".into());
    assert!(r.validate().is_ok());
    r.invitation = Some("03".repeat(32));
    assert!(r.validate().is_err());
}

#[tokio::test]
async fn oversized_or_truncated_frame_is_rejected_before_json_processing() {
    for size in [0u32, protocol::MAX_FRAME_BYTES as u32 + 1, u32::MAX] {
        let bytes = size.to_be_bytes();
        let error = read_request(&mut bytes.as_slice()).await.err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
    let bytes = [0, 0, 0, 5, b'{'];
    assert_eq!(
        read_request(&mut bytes.as_slice())
            .await
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn traffic_open_unknown_fields_and_input_secrets_never_become_error_text() {
    let mut value = serde_json::to_value(request()).unwrap();
    value["SECRET_UNKNOWN_FIELD_WITH_TOKEN"] = "secret-input".into();
    let bytes = frame(&value);
    let error = read_request(&mut bytes.as_slice()).await.err().unwrap();
    assert_eq!(error.to_string(), "invalid enrollment message");
    let bytes =
        frame(&serde_json::json!({"version":1,"host":"target.test","port":443,"transport":"tcp"}));
    assert!(read_request(&mut bytes.as_slice()).await.is_err());
}

#[tokio::test]
async fn transport_cannot_report_distribution_active_or_unbounded_issuer_detail() {
    let bytes = frame(
        &serde_json::json!({"result":"failed","code":"rejected","detail":"private/path/token"}),
    );
    assert!(read_response(&mut bytes.as_slice()).await.is_err());
    let bytes = frame(&serde_json::json!({"result":"failed","code":"private-token"}));
    assert!(read_response(&mut bytes.as_slice()).await.is_err());
    let mut output = Vec::new();
    write_response(
        &mut output,
        &ExchangeResponse::Failed {
            code: FailureCode::Busy,
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        read_response(&mut output.as_slice()).await.unwrap(),
        ExchangeResponse::Failed {
            code: FailureCode::Busy
        }
    ));
}

#[tokio::test]
async fn invalid_challenge_is_rejected_without_writing() {
    let mut output = Vec::new();
    assert!(write_challenge(
        &mut output,
        &ChallengeMessage {
            nonce: "not-a-nonce".into(),
            expires_at_unix_secs: 12
        }
    )
    .await
    .is_err());
    assert!(output.is_empty());
    let challenge = ChallengeMessage {
        nonce: "06".repeat(32),
        expires_at_unix_secs: 12,
    };
    write_challenge(&mut output, &challenge).await.unwrap();
    assert_eq!(
        read_challenge(&mut output.as_slice()).await.unwrap().nonce,
        challenge.nonce
    );
}
