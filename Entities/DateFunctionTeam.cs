using System;
using System.Collections.Generic;

namespace WebApi.Entities
{
    public class DateFunctionTeam
    {
        public DateFunctionTeam(string date, string function)
        {
            Function = function;
            Date = date;
            Users = new List<User>(); 
        }
        public int Id { get; set; }
        public string Date;
        public string Function { get; set; }
        public List<User> Users { get; set; }
    }
}