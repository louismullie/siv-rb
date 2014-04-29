require 'siv-rb/wrapper'
require 'siv-rb/version'

module SIV
  
  class Cipher
    
    def encrypt(pt, ad = [])
      encrypt_native(pt, ad)
    end
    
    def decrypt(ct, ad = [])
      decrypt_native(ct, ad)
    end
    
  end
  
end