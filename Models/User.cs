using System.ComponentModel.DataAnnotations;

namespace ATBM_PRO.Models
{

    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [MaxLength(50)]
        public string Username { get; set; } = string.Empty;

        [Required]
        [MaxLength(255)]
        public string Password { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string HoTen { get; set; } = string.Empty;

        [Required]
        public DateTime NgaySinh { get; set; }

        [Required]
        [MaxLength(10)]
        public string GioiTinh { get; set; } = string.Empty;

        [Required]
        [MaxLength(12)]
        public string SoCCCD { get; set; } = string.Empty;

        [Required]
        [MaxLength(15)]
        public string Sdt { get; set; } = string.Empty;

        [Required]
        [MaxLength(100)]
        public string Email { get; set; } = string.Empty;

        [MaxLength(255)]
        public string DiaChiThuongTru { get; set; } = string.Empty;

        [MaxLength(255)]
        public string DiaChiTamTru { get; set; } = string.Empty;

        [MaxLength(100)]
        public string NgheNghiep { get; set; } = string.Empty;

        [MaxLength(50)]
        public string HonNhan { get; set; } = string.Empty;

        [MaxLength(10)]
        public string BangLaiXe { get; set; } = string.Empty;

        [MaxLength(20)]
        public string SoTKNganHang { get; set; } = string.Empty;

        [Required]
        [MaxLength(10)]
        public string Role { get; set; } = "User";
    }
}
