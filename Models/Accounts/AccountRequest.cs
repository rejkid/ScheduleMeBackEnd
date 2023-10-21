using System.ComponentModel.DataAnnotations;
using WebApi.Entities;
using System.Collections.Generic;
using System;

namespace WebApi.Models.Accounts
{
    public class AccountRequest
    {
        private string _password;
        private string _confirmPassword;
        private string _role;
        private string _email;
        private string _phoneNumber;

        public string Title { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        

        [Required]
        public string Dob { get; set; }

        public UpdateScheduleRequest[] Schedules { get; set; }
        public UpdateUserFunctionRequest[] UserFunctions { get; set; }

        [EnumDataType(typeof(Role))]
        public string Role
        {
            get => _role;
            set => _role = replaceEmptyWithNull(value);
        }

        [EmailAddress]
        public string Email
        {
            get => _email;
            set => _email = replaceEmptyWithNull(value);
        }

        [MinLength(6)]
        public string Password
        {
            get => _password;
            set => _password = replaceEmptyWithNull(value);
        }

        [Compare("Password")]
        public string ConfirmPassword 
        {
            get => _confirmPassword;
            set => _confirmPassword = replaceEmptyWithNull(value);
        }

        public string PhoneNumber
        {
            get => _phoneNumber;
            set => _phoneNumber = replaceEmptyWithNull(value);
        }
        // helpers

        private string replaceEmptyWithNull(string value)
        {
            // replace empty string with null to make field optional
            return string.IsNullOrEmpty(value) ? null : value;
        }
    }
}