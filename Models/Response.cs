namespace BE_Project.Models
{
    public class Response
    {
        public string DataEncryptedbyAes { get; set; } // Dữ liệu đã được mã hóa để trả về FE
        public string AesKeyMasked { get; set; } // Mask đã được mã hóa để trả về FE
        public string MaskEncryptedByRsa { get; set; }
    }
}
