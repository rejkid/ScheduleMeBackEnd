using System;
using System.Collections.Generic;

using WebApi.Entities;
namespace WebApi.Models.Accounts
{
    public class TaskResponse
    {
        public int Id { get; set; }
        
        
        public List<AgentTask> Functions { get; set; }
    }
}