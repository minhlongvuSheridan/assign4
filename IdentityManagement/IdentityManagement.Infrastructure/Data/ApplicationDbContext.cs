using IdentityManagement.Core.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
namespace IdentityManagement.Infrastructure.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser,
ApplicationRole, string>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
    : base(options)

    {
    }
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("Users");
        });
        builder.Entity<ApplicationRole>(entity =>
        {
            entity.ToTable("Roles");
        });
    }
}