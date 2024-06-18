using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities
{
    public class Account : IdentityUser
    {
        
        //[DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        //public int RowId { get; set; }
        public string Title { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        /* Email and passwordHash ... are in IdentityUser  */
        
        public bool AcceptTerms { get; set; }
        public Role Role { get; set; }
        public string VerificationToken { get; set; }
        public DateTime? Verified { get; set; }
        public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
        public string ResetToken { get; set; }
        public DateTime? ResetTokenExpires { get; set; }
        public DateTime? PasswordReset { get; set; }
        public string DOB { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }

        // Notification section
        public bool NotifyWeekBefore { get; set; } = true;
        public bool NotifyThreeDaysBefore { get; set; } = true;
        // End of Notification section

        public List<Schedule> Schedules { get; set; }
        public List<SchedulerTask> UserFunctions { get; set; }
        public List<RefreshToken> RefreshTokens { get; set; }

        public bool OwnsToken(string token) 
        {
            return this.RefreshTokens?.Find(x => x.Token == token) != null;
        }
    }
}