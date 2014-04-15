require 'spec_helper'
require 'siv'

describe SIV do

  it "should fail if key is empty" do
    
    expect { SIV::Cipher.new('') }.to raise_error
    
  end

  it "should fail if incorrect decryption key" do
    
    cipher = SIV::Cipher.new('0' * 32)
    cipher2 = SIV::Cipher.new('1' * 32)
    
    enc = cipher.encrypt("test", [])
    
    expect { cipher2.dec(enc, []) }.to raise_error
    
  end

  it "should pass RFC 5297 spec for deterministic authenticated encryption (A.1)" do
    
    key = ["fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"].pack("H*")
    plaintext = ["112233445566778899aabbccddee"].pack("H*")
    ad = ["101112131415161718191a1b1c1d1e1f2021222324252627"].pack("H*")
    expected = ["85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"].pack("H*")
    
    cipher = SIV::Cipher.new(key)
    enc = cipher.encrypt(plaintext, [ad])
    
    enc.should eql expected
    
    cipher.decrypt(enc, [ad]).should eql plaintext
    
  end

end