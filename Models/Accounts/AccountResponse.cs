using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

using WebApi.Entities;
namespace WebApi.Models.Accounts
{
    public class AccountResponse
    {
        public string Id { get; set; }
        public string Title { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string ScheduleGroup { get; set; } = "";
        [Required]
        public string Dob { get; set; }
        public string Role { get; set; }
        public DateTime Created { get; set; }
        public DateTime? Updated { get; set; }
        public bool IsVerified { get; set; }
        public List<Schedule> Schedules { get; set; }
        public List<SchedulerTask> UserFunctions { get; set; }
    }
}