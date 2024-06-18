using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace WebApi.Entities
{
    public class AgentTaskConfig
    {
        [DefaultValue("1")]
        [Key]
        public int AgentTaskConfigId { get; set; }
        public string AgentTaskStr { get; set; }
        public Boolean IsGroup { get; set; } = false;
    }
}