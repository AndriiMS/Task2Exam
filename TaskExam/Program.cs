using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

//��������� ����������� ������ ��� ������ ������� ����� ���-�����, ���� ������� ������ SQL-�풺���� �� ���������.
public class SQLInjectionDetector
{
    // ����� ��� ���������� �� �������� ��������
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

        // �������� �������� �� ������ �������
        isMalicious = false;
        foreach (var pattern in sqlInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase))
            {
                isMalicious = true;
                break;
            }
        }

        // �������� ��������: ��������� ����������� �������
        string sanitizedInput = Regex.Replace(input, @"['"";\\]", "");

        // ��������� ����������� ����������� �������
        sanitizedInput = sanitizedInput.Replace("<", "&lt;").Replace(">", "&gt;");

        return sanitizedInput;
    }

    // ����� ��� ��������� �������� ������
    public static void LogSuspiciousInput(string input)
    {
        try
        {
            using (StreamWriter writer = new StreamWriter("suspicious_log.txt", true))
            {
                writer.WriteLine($"[{DateTime.Now}] ϳ������� �����: {input}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("������� �� ��� ��������� �������� ������: " + ex.Message);
        }
    }
}
// �������� ��������� ���-����� ��� �������� ������ ������, ������ ����� ���� ���� ����� ������
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
                    <h1>�������� SQL-��'�����</h1>
                    <form method='post' action='/analyze'>
                        <label for='userInput'>������ ��� ��� ������:</label><br/>
                        <textarea id='userInput' name='userInput' rows='5' cols='50'></textarea><br/>
                        <button type='submit'>����������</button>
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
                        <title>��������� ������</title>
                    </head>
                    <body>
                        <h2>������������: �������� �������� �����!</h2>
                        <p>���������� ��������: {userInput}</p>
                        <p>������� ��������: {sanitizedInput}</p>
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
                        <title>��������� ������</title>
                    </head>
                    <body>
                        <h2>����� ���������!</h2>
                        <p>������� ��������: {sanitizedInput}</p>
                    </body>
                    </html>
                ");
            }
        });

        app.Run();
    }
}