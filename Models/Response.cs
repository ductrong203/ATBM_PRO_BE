namespace BE_Project.Models
{
    public class Response
    {
        public string Data { get; set; } // Dữ liệu đã được mã hóa để trả về FE
        public string Mask { get; set; } // Mask đã được mã hóa để trả về FE
    }
}
