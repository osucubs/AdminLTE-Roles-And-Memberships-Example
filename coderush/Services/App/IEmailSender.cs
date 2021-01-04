using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace coderush.Services.App
{
  public interface IEmailSender
  {
    Task SendEmailAsync(string email, string subject, string message);
  }
}