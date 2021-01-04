﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace coderush.Services.App
{
  public class AuthMessageSender : IEmailSender
  {
    // This class is used by the application to send Email and SMS
    // when you turn on two-factor authentication in ASP.NET Identity.
    // For more details see this link http://go.microsoft.com/fwlink/?LinkID=532713

    public Task SendEmailAsync(string email, string subject, string message)
    {
      // Plug in your email service here to send an email.
      return Task.FromResult(0);
    }
  }
}