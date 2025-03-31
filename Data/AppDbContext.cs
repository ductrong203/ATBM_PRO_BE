using Microsoft.EntityFrameworkCore;
using ATBM_PRO.Models;

namespace ATBM_PRO.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
