// AUTHENTICATION WITH TOKEN

//using Microsoft.AspNetCore.Authentication.JwtBearer;
//using Microsoft.AspNetCore.Authentication.OAuth;
//using Microsoft.AspNetCore.Authorization;
//using Microsoft.IdentityModel.Tokens;
//using System.IdentityModel.Tokens.Jwt;
//using System.Security.Claims;
//using System.Text;

//var people = new List<Person>
//{
//    new Person("tom@mail.com", "12345"),
//    new Person("jimmy@mail.com", "pass123")
//};

//var builder = WebApplication.CreateBuilder(args);

//builder.Services.AddAuthorization();

//builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//    .AddJwtBearer(options =>
//    {
//        options.TokenValidationParameters = new TokenValidationParameters
//        {
//            ValidateIssuer = true,
//            // строка, представляющая издателя
//            ValidIssuer = AuthOptions.ISSUER,
//            // будет ли валидироваться потребитель токена
//            ValidateAudience = true,
//            // установка потребителя токена
//            ValidAudience = AuthOptions.AUDIENCE,
//            // будет ли валидироваться время существования
//            ValidateLifetime = true,
//            // установка ключа безопасности
//            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
//            // валидация ключа безопасности
//            ValidateIssuerSigningKey = true,
//        };
//    });

//var app = builder.Build();

//app.UseDefaultFiles();
//app.UseStaticFiles();

//app.UseAuthentication();
//app.UseAuthorization();

//app.MapPost("/login", (Person loginData) =>
//{
//    Person? person = people.FirstOrDefault(p => p.Email == loginData.Email && p.Password == loginData.Password);

//    if (person == null) return Results.Unauthorized();

//    var claims = new List<Claim> { new Claim(ClaimTypes.Name, person.Email) };
//    var jwt = new JwtSecurityToken(
//        issuer: AuthOptions.ISSUER,
//        audience: AuthOptions.AUDIENCE,
//        claims: claims,
//        expires: DateTime.UtcNow.Add(TimeSpan.FromMinutes(2)),
//        signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
//    var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

//    var response = new
//    {
//        access_token = encodedJwt,
//        username = person.Email
//    };

//    return Results.Json(response);
//});

//app.Map("/data", [Authorize] () => new { message = "Authorized!" });

//app.MapGet("/hello", () => "Hello!");

//app.Run();

//public class AuthOptions
//{
//    public const string ISSUER = "MyAuthServer"; // издатель токена
//    public const string AUDIENCE = "MyAuthClient"; // потребитель токена
//    const string KEY = "mysupersecret_secretkey!123";   // ключ для шифрации
//    public static SymmetricSecurityKey GetSymmetricSecurityKey() =>
//        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(KEY));
//}

//record class Person(string Email, string Password);

// ===================================================================================

// AUTHENTICATION WITH COOKIE
// + ROLES

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

Role adminRole = new Role("admin");
Role userRole = new Role("user");
Role potatoRole = new Role("potato");

var people = new List<Person>
{
    new Person("tom@mail.com", "12345", adminRole, "Potato House", 1995),
    new Person("jimmy@mail.com", "pass123", userRole, "Some company", 2012)
};

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme) // CookieAuthenticationDefaults.AuthenticationScheme == "Cookies"
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/accessdenied";
    });
builder.Services.AddTransient<IAuthorizationHandler, AgeHandler>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("OnlyForPotato", policy =>
    {
        policy.RequireClaim("company", "Potato House");
    });
    options.AddPolicy("AgeLimit", policy =>
    {
        policy.Requirements.Add(new AgeRequirement(18));
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.Map("/potato-only", [Authorize(Policy = "OnlyForPotato")] async (HttpContext context) =>
{
    await context.Response.WriteAsync("You are potato!");
});

app.Map("/accessdenied", async (HttpContext context) =>
{
    context.Response.StatusCode = 403;
    await context.Response.WriteAsync("Access denied");
});

app.MapGet("/login", async (HttpContext context) =>
{
    context.Response.ContentType = "text/html; charset=utf-8";
    // html-форма для ввода логина/пароля
    string loginForm = @"<!DOCTYPE html>
    <html>
    <head>
        <meta charset='utf-8' />
        <title>ho-ho-ho</title>
    </head>
    <body>
        <h2>Login Form</h2>
        <form method='post'>
            <p>
                <label>Email</label><br />
                <input name='email' />
            </p>
            <p>
                <label>Password</label><br />
                <input type='password' name='password' />
            </p>
            <input type='submit' value='Login' />
        </form>
    </body>
    </html>";
    await context.Response.WriteAsync(loginForm);
});

app.MapPost("/login", async (string? returnUrl, HttpContext context) =>
{
    var form = context.Request.Form;

    if (!form.ContainsKey("email") || !form.ContainsKey("password"))
        return Results.BadRequest("Email/password is missing");

    string email = form["email"];
    string password = form["password"];

    Person? person = people.FirstOrDefault(p => p.Email == email && p.Password == password);

    if (person == null) return Results.Unauthorized();

    Claim CustomClaim = new Claim("MyClaim", "Some info");
    Claim RoleClaim = new Claim(ClaimsIdentity.DefaultRoleClaimType, person.Role.Name);
    Claim CompanyClaim = new Claim("company", person.Company);
    Claim AgeClaim = new Claim("age", person.Age.ToString());

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, person.Email), CustomClaim, RoleClaim, CompanyClaim, AgeClaim };

    ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));

    return Results.Redirect(returnUrl ?? "/");
});

app.Map("/age", [Authorize(Policy = "AgeLimit")] async (HttpContext context) =>
{
    await context.Response.WriteAsync("You have enough years");
});

app.Map("/admin", [Authorize(Roles = "admin")]async () => "Only admins can see page");

app.Map("/any-user", [Authorize(Roles = "admin, user")] async () => "Any user can see this page");

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.MapGet("/remove-custom-claim", async (HttpContext context) =>
{
    if (context.User.Identity is ClaimsIdentity claimsIdentity)
    {
        var myClaim = claimsIdentity.FindFirst("MyClaim");

        if (claimsIdentity.TryRemoveClaim(myClaim))
        {
            ClaimsPrincipal claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            await context.SignInAsync(claimsPrincipal);

            await context.Response.WriteAsync("All is good");
        }
    }
});

app.Map("/", [Authorize] () => "Authorized Hello World!");

app.Map("/me", async (HttpContext context) => {
    await context.Response.WriteAsync($"user name>>> {context.User.FindFirst(ClaimTypes.Name)?.Value}, custom-claim>>> {context.User.FindFirst("MyClaim")}");
});

app.Run();

class Person
{
    public string Email { get; set; }
    public string Password { get; set; }
    public Role Role { get; set; }
    public string Company { get; set; }
    public int Age { get; set; }

    public Person(string Email, string Password, Role Role, string Company, int Age)
    {
        this.Email = Email;
        this.Password = Password;
        this.Role = Role;
        this.Company = Company;
        this.Age = Age;
    }
}

class Role
{
    public string Name { get; set; }

    public Role(string Name)
    {
        this.Name = Name;
    }
}

class AgeRequirement : IAuthorizationRequirement
{
    protected internal int Age { get; set; }
    public AgeRequirement(int age) => Age = age;
}

class AgeHandler : AuthorizationHandler<AgeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AgeRequirement requirement)
    {
        Console.WriteLine("0000000000000000");
        Claim yearClaim = context.User.FindFirst(c => c.Type == "age");
        if (yearClaim != null)
        {
            Console.WriteLine("111111111111111");
            if (int.TryParse(yearClaim.Value, out int year))
            {
                Console.WriteLine($"year - {year}");
                if ((DateTime.Now.Year - year) >= requirement.Age)
                {
                    context.Succeed(requirement);
                }
            }
        }

        return Task.CompletedTask;
    }
}