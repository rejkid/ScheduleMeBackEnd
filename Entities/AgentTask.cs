using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities
{
    public class AgentTask
    {
        [DefaultValue("1")]
        [Key]
        public int FunctionId { get; set; }
        public string PreferredTime { get; set; }
        public string UserFunction { get; set; }
        public string Group { get; set; }
        public Boolean IsGroup { get; set; } = false;
    }
}