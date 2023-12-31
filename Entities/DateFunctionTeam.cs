using System;
using System.Collections.Generic;

namespace WebApi.Entities
{
    public class DateFunctionTeam
    {
        public DateFunctionTeam(string date, string function)
        {
            UserFunction = function;
            Date = date;
            Users = new List<User>(); 
        }
        public int Id { get; set; }
        public string Date;
        public string UserFunction { get; set; }
        public List<User> Users { get; set; }
    }
}