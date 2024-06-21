using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities
{
    public class AgentTaskConfig
    {
        [Key]
        public string AgentTaskStr { get; set; }
        public Boolean IsGroup { get; set; } = false;
    }
}