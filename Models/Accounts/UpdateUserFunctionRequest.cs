using System.ComponentModel.DataAnnotations;
using WebApi.Entities;
using System.Collections.Generic;
using System;

namespace WebApi.Models.Accounts
{
    public class UpdateUserFunctionRequest
    {
        [Required]
        public string UserFunction { get; set; }
        public string Group { get; set; }
    }
}