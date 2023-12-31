using System;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Models.Accounts
{
    public class ForgotPasswordRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Dob { get; set; }
    }
}