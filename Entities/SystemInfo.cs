using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace WebApi.Entities
{
    public class SystemInfo
    {
        [DefaultValue("1")]
        [Key]
        public int Id { get; set; }
        public uint NoOfEmailsSentDayily { get; set; }
        public bool autoEmail { get; set; }
    }
}