using UnityEngine;
using TMPro;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public class SettingsManager : MonoBehaviour
{
    [System.Serializable]
    public class ConfigData
    {
        public int scan_threshold_seconds;
        public int scan_threshold_ports;
        public List<int> dangerous_ports;
    }

    public TMP_InputField inputScanSeconds;
    public TMP_InputField inputScanPorts;
    public TMP_InputField inputDangerousPorts;

    // 任意の保存場所（例: C:\Users\Public\Documents）
    private string customSavePath = @"C:\Users\nakah\Desktop\metis\config.json";

    void Start()
    {
        LoadConfig();
    }

    public void SaveConfig()
    {
        ConfigData config = new ConfigData();

        // 入力値を取得し、ConfigData に設定
        config.scan_threshold_seconds = int.TryParse(inputScanSeconds.text, out int seconds) ? seconds : 20;
        config.scan_threshold_ports = int.TryParse(inputScanPorts.text, out int ports) ? ports : 3;

        config.dangerous_ports = inputDangerousPorts.text
            .Split(',')
            .Where(s => int.TryParse(s.Trim(), out _))
            .Select(s => int.Parse(s.Trim()))
            .ToList();

        // JSONに変換して保存
        string json = JsonUtility.ToJson(config, true);
        File.WriteAllText(customSavePath, json);
        Debug.Log("[✓] 設定を保存しました: " + customSavePath);
    }

    public void LoadConfig()
    {
        if (!File.Exists(customSavePath))
        {
            Debug.Log("[!] 設定ファイルが見つかりません: " + customSavePath);
            return;
        }

        string json = File.ReadAllText(customSavePath);
        ConfigData config = JsonUtility.FromJson<ConfigData>(json);

        // UIに値を反映
        inputScanSeconds.text = config.scan_threshold_seconds.ToString();
        inputScanPorts.text = config.scan_threshold_ports.ToString();
        inputDangerousPorts.text = string.Join(",", config.dangerous_ports);

        Debug.Log("[✓] 設定を読み込みました: " + customSavePath);
    }
}



