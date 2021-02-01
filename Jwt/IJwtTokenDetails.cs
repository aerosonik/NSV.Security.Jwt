using System;
using System.Collections.Generic;
using System.Text;

namespace NSV.Security.JWT
{
    public interface IJwtTokenDetails
    {
        public TokenDetails Get(string token);
    }
}
