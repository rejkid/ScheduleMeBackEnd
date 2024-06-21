using System.Collections.Generic;
using WebApi.Entities;

namespace WebApi.Models.Accounts
{
    public class AgentTaskConfigResponse
    {
        public List<AgentTaskConfig> taskConfigs { get; set; }
    }
}
