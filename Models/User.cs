using System.ComponentModel.DataAnnotations;

namespace ATBM_PRO.Models
{

    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string HoTen { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string NgaySinh { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string GioiTinh { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string SoCCCD { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string Sdt { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string Email { get; set; } = string.Empty;

        [MaxLength(255)]
        public string DiaChiThuongTru { get; set; } = string.Empty;

        [MaxLength(255)]
        public string DiaChiTamTru { get; set; } = string.Empty;

        [MaxLength(255)]
        public string NgheNghiep { get; set; } = string.Empty;

        [MaxLength(255)]
        public string HonNhan { get; set; } = string.Empty;

        [MaxLength(255)]
        public string BangLaiXe { get; set; } = string.Empty;

        [MaxLength(255)]
        public string SoTKNganHang { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string Role { get; set; } = "User";
    }
}
