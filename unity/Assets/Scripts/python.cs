using UnityEngine;
using System.Diagnostics;
using System.IO;


public class PythonLauncher : MonoBehaviour
{
    public string pythonScriptName = "packet_sniffer.py";
    private Process pythonProcess;

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.P)) // PキーでPython起動
        {
            StartPythonScript();
        }

        if (Input.GetKeyDown(KeyCode.O)) // SキーでPython停止
        {
            StopPythonScript();
        }
    }



    public void StartPythonScript()
    {
        string pythonExe = @"C:\Users\nakah\AppData\Local\Programs\Python\Python311\python.exe"; // ← 修正: "ProgramsPython" ではなく "Programs\Python"
        string scriptPath = @"C:\Users\nakah\Desktop\metis\packet_sniffer.py";

        if (!File.Exists(scriptPath))
        {
            UnityEngine.Debug.LogError("❌ Pythonスクリプトが見つかりません: " + scriptPath);
            return;
        }

        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = pythonExe,
            Arguments = $"\"{scriptPath}\"",
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            pythonProcess = Process.Start(psi);
            UnityEngine.Debug.Log("✅ Pythonスクリプトを実行しました");
        }
        catch (System.Exception e)
        {
            UnityEngine.Debug.LogError("❌ 起動失敗: " + e.Message);
        }
    }

    public void StopPythonScript()
    {
        if (pythonProcess != null && !pythonProcess.HasExited)
        {
            pythonProcess.Kill();
            UnityEngine.Debug.Log("🛑 Pythonスクリプトを停止しました");
        }
        else
        {
            UnityEngine.Debug.Log("（Pythonはすでに停止しています）");
        }
    }
}



