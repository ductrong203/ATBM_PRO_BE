using System.Text.Json.Serialization;

namespace BE_Project.Models
{
    public class Request
    {
        public string DataEncryptedByAes { get; set; } // Dữ liệu đã XOR với mask
        public string AesKeyMasked { get; set; } // Mask đã được mã hóa bằng RSA
        public string MaskEncryptedByRsa { get; set; }
        public PublicKey PublicKeyFE { get; set; } // Public key của FE gửi lên
    }

    public class PublicKey
    {
        public string n { get; set; }  // Modulus của khóa công khai
        public string e { get; set; }  // Exponent của khóa công khai
    }
    public class ChangePasswordRequest
    {  public string OldPassword { get; set; }
       public string NewPassword { get; set; }
    }
    public class LoginRq
    {
        public string Username { get; set; }

        public string Password { get; set; }
    }
}


