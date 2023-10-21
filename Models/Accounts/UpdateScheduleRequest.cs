using System.ComponentModel.DataAnnotations;
using WebApi.Entities;
using System.Collections.Generic;
using System;

namespace WebApi.Models.Accounts
{
    public class UpdateScheduleRequest
    {
        [Required]
        public string Date { get; set; }
        public string NewDate { get; set; }
        [Required]
        public Boolean Required { get; set; }
        public Boolean UserAvailability { get; set; }
        public string UserFunction { get; set; }
        public string NewUserFunction { get; set; }
        public string ScheduleGroup { get; set; }
    }
}