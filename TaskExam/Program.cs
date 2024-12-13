using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

//Реалізація програмного модулю для аналізу вхідних даних веб-форми, який виявляє спроби SQL-ін’єкції за патернами.
public class SQLInjectionDetector
{
    // Метод для фільтрації та перевірки введення
    public static string SanitizeAndCheckInput(string input, out bool isMalicious)
    {
        string[] sqlInjectionPatterns =
        {
        "--", ";--", ";", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --",
        "' OR 'x'='x", "\" OR \"x\"=\"x", "' OR 1=1#", "1=1", "\\\\\" OR \\\\\"1\\\\\"=\\\\\"1",
        "\\\\' OR \\\\'1\\\\'=\\\\'1", "exec\\(", "exec xp_", "sp_", "0x", "(?i)DROP TABLE",
        "(?i)SELECT \\* FROM", "(?i)INSERT INTO", "(?i)DELETE FROM", "(?i)UPDATE .* SET",
        "(?i)ALTER TABLE", "(?i)CREATE TABLE", "(?i)UNION SELECT", "(?i)--", "\\bOR\\b",
        "\\bAND\\b", "\\bNOT\\b", "\\bLIKE\\b", "\\bWHERE\\b", "\\bHAVING\\b", "\\bCAST\\b",
        "\\bCONVERT\\b", "(?i)CHAR\\(", "(?i)NCHAR\\(", "(?i)WAITFOR DELAY", "(?i)OPENROWSET",
        "(?i)INFORMATION_SCHEMA"
    };

        // Перевірка введення на шкідливі патерни
        isMalicious = false;
        foreach (var pattern in sqlInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                isMalicious = true;
                break;
            }
        }

        // Очищення введення: видалення небезпечних символів
        string sanitizedInput = Regex.Replace(input, @"['"";\\]", "");

        // Додаткове екранування спеціальних символів
        sanitizedInput = sanitizedInput.Replace("<", "&lt;").Replace(">", "&gt;");

        return sanitizedInput;
    }

    // Метод для логування підозрілих запитів
    public static void LogSuspiciousInput(string input)
    {
        try
        {
            using (StreamWriter writer = new StreamWriter("suspicious_log.txt", true))
            {
                writer.WriteLine($"[{DateTime.Now}] Підозрілий запит: {input}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Помилка під час логування підозрілих запитів: " + ex.Message);
        }
    }
}
// Невелика реалізація веб-форми для перевірки роботи модулю, замість цього може бути інший модуль
public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var app = builder.Build();

        app.MapGet("/", async context =>
        {
            context.Response.ContentType = "text/html; charset=UTF-8";
            await context.Response.WriteAsync(@"
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset='UTF-8'>
                    <title>SQL Injection Detector</title>
                </head>
                <body>
                    <h1>Перевірка SQL-ін'єкцій</h1>
                    <form method='post' action='/analyze'>
                        <label for='userInput'>Введіть дані для аналізу:</label><br/>
                        <textarea id='userInput' name='userInput' rows='5' cols='50'></textarea><br/>
                        <button type='submit'>Аналізувати</button>
                    </form>
                </body>
                </html>
            ");
        });

        app.MapPost("/analyze", async context =>
        {
            context.Response.ContentType = "text/html; charset=UTF-8";

            var form = await context.Request.ReadFormAsync();
            string userInput = form["userInput"];

            bool isMalicious;
            string sanitizedInput = SQLInjectionDetector.SanitizeAndCheckInput(userInput, out isMalicious);

            if (isMalicious)
            {
                await context.Response.WriteAsync($@"
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset='UTF-8'>
                        <title>Результат аналізу</title>
                    </head>
                    <body>
                        <h2>Попередження: Виявлено шкідливий рядок!</h2>
                        <p>Оригінальне введення: {userInput}</p>
                        <p>Очищене введення: {sanitizedInput}</p>
                    </body>
                    </html>
                ");
                SQLInjectionDetector.LogSuspiciousInput(userInput);
            }
            else
            {
                await context.Response.WriteAsync($@"
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <meta charset='UTF-8'>
                        <title>Результат аналізу</title>
                    </head>
                    <body>
                        <h2>Рядок безпечний!</h2>
                        <p>Очищене введення: {sanitizedInput}</p>
                    </body>
                    </html>
                ");
            }
        });

        app.Run();
    }
}