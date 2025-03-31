using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ATBM_PRO.Data;
using System.Numerics;
using ATBM_PRO.Models;
using System.Text.Json;
using BCrypt.Net;
using ATBM_PRO.Services;
using System.Threading.Tasks;
using BE_Project.Models;
using Microsoft.AspNetCore.Identity.Data;
using System.Text.Encodings.Web;

namespace ATBM_PRO.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly EncryptionService _encryptionService;

        public UserController(AppDbContext context, EncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        // 📌 API lấy Public Key
        [HttpGet("public-key")]
        public IActionResult GetPublicKey()
        {
            var publicKey = _encryptionService.GetPublicKey();
            return Ok(new { n = publicKey.n.ToString(), e = publicKey.e.ToString() });
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Request request)
        {
            try
            {
                // 🔓 Giải mã request từ client
                string decryptedJson = _encryptionService.DecryptRequest(request.Data, request.Mask);
                var loginRequest = JsonSerializer.Deserialize<BE_Project.Models.LoginRequest>(decryptedJson);
                if (loginRequest == null) return BadRequest("Dữ liệu không hợp lệ.");

                // 🔍 Tìm user trong DB (dữ liệu đã mã hóa)
                var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loginRequest.Username);
                if (user == null) return Unauthorized("Email hoặc mật khẩu không đúng.");

                // 🔑 Giải mã mật khẩu đã lưu (so sánh với mật khẩu nhập vào)
                if (!BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.Password))
                    return Unauthorized("Email hoặc mật khẩu không đúng.");

                var (nFE, eFE) = (BigInteger.Parse(request.PublicKeyFE.n), BigInteger.Parse(request.PublicKeyFE.e));

                // Tạo đối tượng user không chứa password
                var userResponse = new
                {
                    user.Id,
                    user.Username,
                    user.HoTen,
                    user.NgaySinh,
                    user.GioiTinh,
                    user.SoCCCD,
                    user.Sdt,
                    user.Email,
                    user.DiaChiThuongTru,
                    user.DiaChiTamTru,
                    user.NgheNghiep,
                    user.HonNhan,
                    user.BangLaiXe,
                    user.SoTKNganHang,
                    user.Role
                };

                var response = new { 
                    Message = "Đăng nhập thành công",
                    User = userResponse
                };

                var options = new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };

                return Ok(_encryptionService.EncryptResponse(JsonSerializer.Serialize(response, options), nFE, eFE));
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Lỗi: {ex.Message}");
            }
        }

        [HttpPost]
        // 📌 API Đăng ký User (Giải mã request & Mã hóa response)
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Request request)
        {
            try
            {
                // 🔓 Giải mã dữ liệu từ request
                string decryptedJson = _encryptionService.DecryptRequest(request.Data, request.Mask);
                var user = JsonSerializer.Deserialize<User>(decryptedJson);
                if (user == null) return BadRequest("Dữ liệu không hợp lệ.");
               /* user.Name = Convert.ToBase64String(_encryptionService.EncryptString(user.Name, _encryptionService.GetEncryptionKey()));
                user.Email = Convert.ToBase64String(_encryptionService.EncryptString(user.Email, _encryptionService.GetEncryptionKey()));
                user.Phone = Convert.ToBase64String(_encryptionService.EncryptString(user.Phone, _encryptionService.GetEncryptionKey()));
                user.Address = Convert.ToBase64String(_encryptionService.EncryptString(user.Address, _encryptionService.GetEncryptionKey()));
               */
                // Mã hóa mật khẩu
                user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);
                _context.Users.Add(user);
                await _context.SaveChangesAsync();

                var (nFE, eFE) = (BigInteger.Parse(request.PublicKeyFE.n), BigInteger.Parse(request.PublicKeyFE.e));

                var options = new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                // 🔒 Mã hóa dữ liệu trả về
                return Ok(_encryptionService.EncryptResponse(JsonSerializer.Serialize(user, options), nFE, eFE));
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Lỗi: {ex.Message}");
                Console.WriteLine($"StackTrace: {ex.StackTrace}");
                return StatusCode(500, $"Lỗi: {ex.Message}");
            }
        }

        // 📌 API Lấy danh sách Users (Mã hóa response)
        [HttpGet()]
        public async Task<IActionResult> GetUsers([FromQuery] string n, [FromQuery] string e)
        {
            try
            {
                var users = await _context.Users.ToListAsync();
                var usersJson = JsonSerializer.Serialize(users);
                /*foreach (var user in users)
                {
                    user.Name = _encryptionService.DecryptString(Convert.FromBase64String(user.Name), _encryptionService.GetEncryptionKey());
                    user.Email = _encryptionService.DecryptString(Convert.FromBase64String(user.Email), _encryptionService.GetEncryptionKey());
                    user.Phone = _encryptionService.DecryptString(Convert.FromBase64String(user.Phone), _encryptionService.GetEncryptionKey());
                    user.Address = _encryptionService.DecryptString(Convert.FromBase64String(user.Address), _encryptionService.GetEncryptionKey());
                }
                */
                // 🔒 Mã hóa phản hồi
                return Ok(_encryptionService.EncryptResponse(usersJson, BigInteger.Parse(n), BigInteger.Parse(e)));
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Lỗi xử lý yêu cầu: {ex.Message}");
            }
        }

        // 📌 API Lấy User theo ID (Mã hóa response)
        [HttpGet("{id}")]
        public async Task<IActionResult> GetUser(int id, [FromQuery] string n, [FromQuery] string e)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            var options = new JsonSerializerOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
            };

            // 🔒 Mã hóa phản hồi
            return Ok(_encryptionService.EncryptResponse(JsonSerializer.Serialize(user, options), BigInteger.Parse(n), BigInteger.Parse(e)));
        }

        // 📌 API Cập nhật User (Giải mã request)
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateUser(int id, [FromBody] Request request)
        {
            try
            {
                // 🔓 Giải mã request
                string decryptedJson = _encryptionService.DecryptRequest(request.Data, request.Mask);
                var user = JsonSerializer.Deserialize<User>(decryptedJson);
                if (user == null || id != user.Id) return BadRequest();

                _context.Entry(user).State = EntityState.Modified;
                await _context.SaveChangesAsync();
                var (nFE, eFE) = (BigInteger.Parse(request.PublicKeyFE.n), BigInteger.Parse(request.PublicKeyFE.e));

                var options = new JsonSerializerOptions
                {
                    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                };
                // 🔒 Mã hóa dữ liệu trả về
                return Ok(_encryptionService.EncryptResponse(JsonSerializer.Serialize(user, options), nFE, eFE));
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Lỗi: {ex.Message}");
            }
        }

        // 📌 API Xóa User (Mã hóa response)
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(int id, [FromQuery] string n, [FromQuery] string e)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return NotFound();

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();

            // 🔒 Mã hóa phản hồi
            return Ok(_encryptionService.EncryptResponse(JsonSerializer.Serialize(new { message = "Xóa thành công" }), BigInteger.Parse(n), BigInteger.Parse(e)));
        }
    }
}
