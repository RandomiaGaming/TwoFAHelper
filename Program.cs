using System;
using System.Drawing;
using System.Linq;
using System.Text;
using QRCoder;
using System.Security.Cryptography;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using System.Diagnostics;

namespace TwoFAHelper
{
    public static class Program
    {
        public static string GenerateTOTP(byte[] secret)
        {
            // Get the current time floored to the nearest group of 30 seconds
            long counterValue = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
            // Convert that time to bytes
            byte[] counterBytes = BitConverter.GetBytes(counterValue);
            // Account for endiannes
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }
            // Get the hmac sha1 of the current time with the secret key
            HMACSHA1 hmacsha1 = new HMACSHA1(secret);
            byte[] hash = hmacsha1.ComputeHash(counterBytes);
            hmacsha1.Dispose();
            // Offset is the low 4 bits of the last byte of the hash
            int offset = hash[hash.Length - 1] & 0x0F;
            // Get the four bytes from offset in the hash
            byte[] outputBytes = new byte[] { hash[offset + 0], hash[offset + 1], hash[offset + 2], hash[offset + 3] };
            // Account for endianness
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(outputBytes);
            }
            // Convert those 4 bytes to an integer
            int output = BitConverter.ToInt32(outputBytes, 0);
            // Make sure the output integer is always positive by setting the sign bit to 0
            output &= int.MaxValue;
            // Mod the output with 1,000,000 to ensure it's always a 6 digit number
            output %= 1000000;
            // Return output to string and padded with 0s so 15 becomes 000015
            return $"{output:000000}";
        }
        public static Bitmap CreateTOTPQRCode(string lable, byte[] secret, string issuer)
        {
            // Create the URI in the correct format based upon input parameters
            string uri;
            if (issuer is null || issuer == "")
            {
                uri = $"otpauth://totp/{UrlEscapeString(lable)}?secret={Base32EncodeBytes(secret)}";
            }
            else
            {
                uri = $"otpauth://totp/{UrlEscapeString(lable)}?secret={Base32EncodeBytes(secret)}&issuer={UrlEscapeString(issuer)}";
            }
            // Turn the uri into a QRCode
            QRCodeGenerator qrCodeGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrCodeGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode(qrCodeData);
            // Turn the QRCode into a renderred Bitmap
            Bitmap output = qrCode.GetGraphic(5);
            // Cleanup and return the output Bitmap
            qrCode.Dispose();
            qrCodeData.Dispose();
            qrCodeGenerator.Dispose();
            return output;
        }
        private const string Base32Charset = "abcdefghijklmnopqrstuvwxyz234567";
        public static string Base32EncodeBytes(byte[] value)
        {
            // Set up int buffer to store bits
            int outputCapacity = ((value.Length * 8) + 4) / 5;
            int outputLength = 0;
            char[] output = new char[outputCapacity];
            int bitBuffer = 0;
            int bitBufferLength = 0;
            // Loop over each byte in the input
            foreach (byte b in value)
            {
                // Add the 8 bits from each byte to the buffer
                bitBuffer = (bitBuffer << 8) | b;
                bitBufferLength += 8;
                // The convert as much of the buffer to chars as possible until we run out of 5 bit chunks
                while (bitBufferLength >= 5)
                {
                    int charIndex = (bitBuffer >> (bitBufferLength - 5)) & 0x1F;
                    bitBufferLength -= 5;
                    output[outputLength] = Base32Charset[charIndex];
                    outputLength++;
                }
            }
            // If at the end we are left with a chunk of bits smaller than 5 then pad with 0s
            if (bitBufferLength > 0)
            {
                int charIndex = (bitBuffer << (5 - bitBufferLength)) & 0x1F;
                output[outputLength] = Base32Charset[charIndex];
                outputLength++;
            }
            // Return the finished output
            return new string(output);
        }
        public static byte[] Base32DecodeString(string value)
        {
            // Set up int buffer to store bits
            int outputCapacity = value.Length * 5 / 8;
            int outputLength = 0;
            byte[] output = new byte[outputCapacity];
            int bitBuffer = 0;
            int bitBufferLength = 0;
            // Loop over each char in the input
            foreach (char c in value)
            {
                // Add the 5 bits from each char to the buffer
                int charIndex = Base32Charset.IndexOf(c);
                // Throw an error if we stumble upon an invalid char
                if (charIndex == -1)
                {
                    throw new Exception($"Invalid character in Base32 string \"{c}\".");
                }
                bitBuffer = (bitBuffer << 5) | charIndex;
                bitBufferLength += 5;
                // The convert as much of the buffer to bytes as possible until we run out of 8 bit chunks
                while (bitBufferLength >= 8)
                {
                    output[outputLength] = (byte)((bitBuffer >> (bitBufferLength - 8)) & 0xFF);
                    bitBufferLength -= 8;
                    outputLength++;
                }
            }
            // If we end with bits left and they are not 0s something went wrong
            if (bitBufferLength > 0 && (bitBuffer & ((1 << bitBufferLength) - 1)) != 0)
            {
                throw new Exception("Base32 string had invalid padding or leftover bits.");
            }
            // Return the finished output
            return output;
        }
        private const string URLValidCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
        public static string UrlEscapeString(string value)
        {
            // Loop over each char and if its in the URLValidCharset
            StringBuilder output = new StringBuilder();
            for (int i = 0; i < value.Length; i++)
            {
                if (!URLValidCharset.Contains(value[i]))
                {
                    // Chars not in the URLValidCharset must be escaped in the form %HexCharcode
                    output.Append($"%{((int)value[i]):X2}");
                }
                else
                {
                    // Chars in the URLValidCharset may be left as is
                    output.Append(value[i]);
                }
            }
            // Return output
            return output.ToString();
        }
        public static byte[] GetCryptoRandomBytes(int outputLength)
        {
            // Create an array to store the output
            byte[] output = new byte[outputLength];
            // Generate the cyptographically secure random bytes
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(output);
            rng.Dispose();
            // Return the output
            return output;
        }
        public static void ShowBitmapInPopup(Bitmap bitmap)
        {
            BitmapDisplayForm bitmapDisplayForm = new BitmapDisplayForm(bitmap);
            bitmapDisplayForm.ShowDialog();
        }
        private class BitmapDisplayForm : Form
        {
            private Bitmap _bitmap;
            public BitmapDisplayForm(Bitmap bitmap)
            {
                _bitmap = bitmap;
                ResizeRedraw = true;
                StartPosition = FormStartPosition.Manual;
                Rectangle screenBounds = Screen.PrimaryScreen.Bounds;
                int size = Math.Min(screenBounds.Width, screenBounds.Height) / 2;
                ClientSize = new Size(size, size);
                int x = screenBounds.X + ((screenBounds.Width - size) / 2);
                int y = screenBounds.Y + ((screenBounds.Height - size) / 2);
                Location = new Point(x, y);
            }
            protected override void OnPaint(PaintEventArgs e)
            {
                e.Graphics.PixelOffsetMode = PixelOffsetMode.Half;
                e.Graphics.InterpolationMode = InterpolationMode.NearestNeighbor;
                e.Graphics.Clear(Color.FromArgb(255, 0, 0));
                e.Graphics.DrawImage(_bitmap, new Rectangle(0, 0, ClientSize.Width, ClientSize.Height), new Rectangle(0, 0, _bitmap.Width, _bitmap.Height), GraphicsUnit.Pixel);
            }
            protected override void OnResize(EventArgs e)
            {
                base.OnResize(e);
                Invalidate();
            }
        }
        public static void Command_GenerateQR(string[] args)
        {
            string lable = null;
            byte[] secret = null;
            string issuer = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].ToLower() == "/lable".ToLower())
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("No value supplied with the /lable argument to the subcommand --generate-qr.");
                    }
                    else if (!(lable is null))
                    {
                        throw new Exception("A value has already be supplied for the parameter lable of --generate-qr.");
                    }
                    else
                    {
                        i++;
                        lable = args[i];
                    }
                }
                else if (args[i].ToLower() == "/secret".ToLower())
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("No value supplied with the /secret argument to the subcommand --generate-qr.");
                    }
                    else if (!(secret is null))
                    {
                        throw new Exception("A value has already be supplied for the parameter secret of --generate-qr.");
                    }
                    else
                    {
                        i++;
                        secret = Base32DecodeString(args[i]);
                    }
                }
                else if (args[i].ToLower() == "/issuer".ToLower())
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("No value supplied with the /issuer argument to the subcommand --generate-qr.");
                    }
                    else if (!(issuer is null))
                    {
                        throw new Exception("A value has already be supplied for the parameter issuer of --generate-qr.");
                    }
                    else
                    {
                        i++;
                        issuer = args[i];
                    }
                }
                else
                {
                    throw new Exception($"Unknown argument \"{args[i]}\" given to subcommand --generate-qr.");
                }
            }

            bool logSecret = false;
            if (lable is null)
            {
                lable = "Unnamed TOTP";
            }
            if (secret is null)
            {
                logSecret = true;
                secret = GetCryptoRandomBytes(20);
            }
            Bitmap qrCode = CreateTOTPQRCode(lable, secret, issuer);
            Console.WriteLine("TOTP QR code created.");
            if (logSecret)
            {
                Console.WriteLine($"Using random secret: {Base32EncodeBytes(secret)}");
            }
            Console.WriteLine("Now displaying qr code. Press X to close popup.");
            ShowBitmapInPopup(qrCode);
            qrCode.Dispose();
        }
        public static void Command_GetOtp(string[] args)
        {
            byte[] secret = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].ToLower() == "/secret".ToLower())
                {
                    if (i + 1 >= args.Length)
                    {
                        throw new Exception("No value supplied with the /secret argument to the subcommand --get-otp.");
                    }
                    else if (!(secret is null))
                    {
                        throw new Exception("A value has already be supplied for the parameter secret of --get-otp.");
                    }
                    else
                    {
                        i++;
                        secret = Base32DecodeString(args[i]);
                    }
                }
                else
                {
                    throw new Exception($"Unknown argument \"{args[i]}\" given to subcommand --get-otp.");
                }
            }

            if (secret is null)
            {
                throw new Exception("No value supplied for required argument secret of subcommand --get-otp.");
            }
            Console.WriteLine(GenerateTOTP(secret));
        }
        public static void PressAnyKeyToExit()
        {
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Stopwatch inputBufferTimer = Stopwatch.StartNew();
            while (true)
            {
                Console.ReadKey(true);
                if (inputBufferTimer.ElapsedTicks > 10000000)
                {
                    break;
                }
            }
            Environment.Exit(0);
            Process.GetCurrentProcess().Kill();
        }
        public static int Main(string[] args)
        {
            try
            {
                if (args is null || args.Length == 0 || args[0].ToLower() == "--help".ToLower() || args[0].ToLower() == "/?".ToLower())
                {
                    Console.WriteLine("USAGE: TwoFAHelper.exe --generate-qr [/lable LableHere] [/secret SecretKeyHere] [/issuer IssuerNameHere]");
                    Console.WriteLine("USAGE: TwoFAHelper.exe --generate-qr /lable CoolCat@example.com /secret s4gnvxgqote3kaktbayfxwiqubju45ob /issuer Example");
                    Console.WriteLine("USAGE: TwoFAHelper.exe --get-otp /secret SecretKeyHere");
                    Console.WriteLine("USAGE: TwoFAHelper.exe --get-otp /secret s4gnvxgqote3kaktbayfxwiqubju45ob");
                }
                else if (args[0].ToLower() == "--generate-qr".ToLower())
                {
                    string[] trimmedArgs = new string[args.Length - 1];
                    Array.Copy(args, 1, trimmedArgs, 0, trimmedArgs.Length);
                    Command_GenerateQR(trimmedArgs);
                }
                else if (args[0].ToLower() == "--get-otp".ToLower())
                {
                    string[] trimmedArgs = new string[args.Length - 1];
                    Array.Copy(args, 1, trimmedArgs, 0, trimmedArgs.Length);
                    Command_GetOtp(trimmedArgs);
                }
                else
                {
                    throw new Exception($"\"{args[0]}\" is not a valid subcommand. Run TwoFAHelper.exe --help for usage.");
                }
                if (Debugger.IsAttached)
                {
                    PressAnyKeyToExit();
                }
                return 0;
            }
            catch (Exception ex)
            {
                ConsoleColor originalColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"ERROR: {ex.Message}");
                Console.ForegroundColor = originalColor;
                return 1;
            }
        }
    }
}
