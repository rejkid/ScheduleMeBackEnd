using System.ComponentModel.DataAnnotations;
using WebApi.Entities;
using System.Collections.Generic;
using System;

namespace WebApi.Models.Accounts
{
    public class AccountsByDateAndTaskDTO
    {
        [Required]
        public string DateStr { get; set; }
        [Required]
        public string Task { get; set; }
    }
}