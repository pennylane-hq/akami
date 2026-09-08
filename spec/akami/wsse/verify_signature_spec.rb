require "spec_helper"

describe Akami::WSSE::VerifySignature do
  it "validates correctly signed XML messages" do
    xml = fixture("akami/wsse/verify_signature/valid.xml")
    validator = described_class.new(xml)
    expect(validator.verify!).to eq(true)
  end

  it "validates correctly signed XML messages with multiple binary security token" do
    xml = fixture("akami/wsse/verify_signature/valid_multiple_binary_security_token.xml")
    validator = described_class.new(xml)
    expect(validator.verify!).to eq(true)
  end

  it "validates correctly signed XML messages with differently named namespaces" do
    xml = fixture("akami/wsse/verify_signature/valid_namespaces.xml")
    validator = described_class.new(xml)
    expect(validator.verify!).to eq(true)
  end

  it "validates correctly signed XML messages whose signed elements are indented" do
    xml = fixture("akami/wsse/verify_signature/valid_indented_signed_elements.xml")
    validator = described_class.new(xml, decrypted_attachments: indented_fixture_attachments)
    expect(validator.verify!).to equal(true)
  end

  it "does not validate signed XML messages reformatted after being signed" do
    xml = fixture("akami/wsse/verify_signature/invalid_whitespace_reformatted.xml")
    validator = described_class.new(xml)
    expect { validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it "does not validate signed XML messages with digested content changed" do
    xml = fixture("akami/wsse/verify_signature/invalid_digested_changed.xml")
    validator = described_class.new(xml)
    expect { validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it "does not validate signed XML messages with digest changed" do
    xml = fixture("akami/wsse/verify_signature/invalid_digest_changed.xml")
    validator = described_class.new(xml)
    expect { validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it "does not validate signed XML messages with signature changed" do
    xml = fixture("akami/wsse/verify_signature/invalid_signature_changed.xml")
    validator = described_class.new(xml)
    expect { validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  it "validates correctly signed XML messages with SHA256 signature and SHA256 digests" do
    xml = fixture("akami/wsse/verify_signature/valid_sha256.xml")
    validator = described_class.new(xml)
    expect(validator.verify!).to equal(true)
  end

  it "validates correctly signed XML messages with inclusive namespaces in transforms" do
    xml = fixture("akami/wsse/verify_signature/valid_indented_with_inclusive_namespaces.xml")
    validator = described_class.new(xml)
    expect(validator.verify!).to equal(true)
  end

  it "does not validate messages with inclusive namespaces reformatted after being signed" do
    xml = fixture("akami/wsse/verify_signature/invalid_whitespace_reformatted_inclusive_namespaces.xml")
    validator = described_class.new(xml)
    expect { validator.verify! }.to raise_error(Akami::WSSE::InvalidSignature)
  end

  private

  def indented_fixture_attachments
    {
      "attachment-99999999-8888-7777-6666-555555555555@example.com" =>
        "akami-verify-signature-attachment-payload"
    }
  end
end
