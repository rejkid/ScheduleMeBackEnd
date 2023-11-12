using log4net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Configuration;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using WebApi.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.Reflection;

namespace WebApi.Helpers
{
    public class DataContext : IdentityDbContext<Account>
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public DbSet<SystemInfo> SystemInformation { get; set; }

        public DbSet<Account> Accounts { get; set; }
        public DbSet<Schedule> Schedules { get; set; }

        public DbSet<Function> UserFunctions { get; set; }
        public DbSet<SchedulePoolElement> SchedulePoolElements { get; set; }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

        private readonly IConfiguration Configuration;


        //public DataContext(IConfiguration configuration)
        //{
        //    Configuration = configuration;

        //}

        public DataContext(IConfiguration configuration, DbContextOptions options) : base(options)
        {
            Configuration = configuration;
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            // connect to sqlite database
            options.UseSqlite(Configuration.GetConnectionString("WebApiDatabase"));
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            //modelBuilder.Entity<Account>().HasMany(e => e.RefreshTokens).WithOne(e => e.Account).IsRequired();
            modelBuilder.Entity<SystemInfo>().HasData(
            new SystemInfo
            {
                Id = 1,
                NoOfEmailsSentDayily = 1,
                autoEmail = false
            });
            modelBuilder.Entity<Account>()
                .HasMany<Schedule>(a => a.Schedules)
                .WithOne()
                .OnDelete(DeleteBehavior.ClientCascade);
            modelBuilder.Entity<Account>()
                .HasMany<Function>(a => a.UserFunctions)
                .WithOne()
                .OnDelete(DeleteBehavior.ClientCascade);
            modelBuilder.Entity<Account>()
                .HasMany<RefreshToken>(a => a.RefreshTokens)
                .WithOne(r => r.Account)
                .OnDelete(DeleteBehavior.ClientCascade);
        }
        public bool IsDisposed()
        {
            bool result = true;
            var typeDbContext = typeof(DbContext);
            var isDisposedTypeField = typeDbContext.GetField("_disposed", BindingFlags.NonPublic | BindingFlags.Instance);

            if (isDisposedTypeField != null)
            {
                result = (bool)isDisposedTypeField.GetValue(this);
            }

            return result;
        }
    }
}