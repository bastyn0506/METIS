using UnityEngine;
using TMPro;
using System.Collections.Generic;

public class AlertConsoleManager : MonoBehaviour
{
    public TextMeshProUGUI alertText; // 👈 ここにTextMeshProオブジェクトをアサインする
    private Queue<string> alertLogs = new Queue<string>();
    private int maxLogs = 10; // 最大何行まで表示するか

    public void AddAlert(string message)
    {
        if (alertLogs.Count >= maxLogs)
        {
            alertLogs.Dequeue(); // 古いやつを削除
        }

        alertLogs.Enqueue(message);
        alertText.text = string.Join("\n", alertLogs.ToArray()); // ログをまとめて表示
    }
}

