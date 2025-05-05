using UnityEngine;
using TMPro;
using System.Collections.Generic;

public class PortStatsUI : MonoBehaviour
{
    [Header("固定ポートUI")]
    public Transform fixedPortParent;

    [Header("動的ポートUI")]
    public Transform dynamicPortParent;

    public GameObject textPrefab;

    [Header("フォントアセット")]
    public TMP_FontAsset normalFont;
    public TMP_FontAsset dangerFont;

    private Dictionary<int, Dictionary<string, int>> portStats = new();
    private HashSet<int> dangerPorts = new(); // ← 動的に更新される危険ポート

    public List<int> fixedPorts = new() { 53, 80, 443 };

    // キャッシュ用
    private AlertConsoleManager alertManager;
    private AlertEffectManager alertEffect;

    void Start()
    {
        // アラート用スクリプトの取得（1回のみ）
        alertManager = FindObjectOfType<AlertConsoleManager>();
        alertEffect = FindObjectOfType<AlertEffectManager>();

        InvokeRepeating(nameof(UpdateUI), 1f, 1f);
    }

    // 危険ポートを外部から更新する用
    public void UpdateDangerPorts(List<int> dangerPortList)
    {
        dangerPorts = new HashSet<int>(dangerPortList);
        Debug.Log("⚠️ 危険ポート一覧を更新: " + string.Join(", ", dangerPorts));
    }

    public void UpdatePortIPStats(Dictionary<int, Dictionary<string, int>> newStats)
    {
        portStats = newStats;
        UpdateUI();

        foreach (var entry in portStats)
        {
            int port = entry.Key;
            Dictionary<string, int> ipCounts = entry.Value;

            if (dangerPorts.Contains(port))
            {
                foreach (var ipEntry in ipCounts)
                {
                    string ip = ipEntry.Key;
                    alertManager?.AddAlert($"　警告　危険ポート{port}にアクセスあり: {ip}からアクセス");
                    alertEffect?.TriggerAlert();
                }
            }
        }
    }

    void UpdateUI()
    {
        Debug.Log("🌀 UI更新時のdangerPorts状態: " + string.Join(", ", dangerPorts));
        foreach (Transform child in fixedPortParent) Destroy(child.gameObject);
        foreach (Transform child in dynamicPortParent) Destroy(child.gameObject);

        foreach (var entry in portStats)
        {
            int port = entry.Key;
            Dictionary<string, int> ipCounts = entry.Value;

            Debug.Log($"🖥 ポート {port} に IP数: {ipCounts.Count}");

            Transform targetParent = fixedPorts.Contains(port) ? fixedPortParent : dynamicPortParent;

            GameObject textObj = Instantiate(textPrefab, targetParent);
            var text = textObj.GetComponent<TextMeshProUGUI>();
            text.font = dangerPorts.Contains(port) ? dangerFont : normalFont;

            System.Text.StringBuilder sb = new();
            sb.AppendLine($"ポート {port}：");
            foreach (var ip in ipCounts)
            {
                Debug.Log($"└ {ip.Key} から {ip.Value} 回");
                sb.AppendLine($"└ {ip.Key}：{ip.Value} 回");
            }
            text.text = sb.ToString();
        }

        // 通信のない固定ポートを補完
        foreach (int fixedPort in fixedPorts)
        {
            if (portStats.ContainsKey(fixedPort)) continue;

            GameObject textObj = Instantiate(textPrefab, fixedPortParent);
            var text = textObj.GetComponent<TextMeshProUGUI>();
            text.font = dangerPorts.Contains(fixedPort) ? dangerFont : normalFont;
            text.text = $"ポート {fixedPort}：\n└ 通信なし";
        }
    }
}






