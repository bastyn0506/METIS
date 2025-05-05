using UnityEngine;

public class DisplaySwitcher : MonoBehaviour
{
    public Camera mainCamera;
    private bool usingDisplay2 = false;

    void Start()
    {
        if (Display.displays.Length > 1)
        {
            Display.displays[1].Activate(); // Display 2 を有効化
        }

        // 初期はDisplay 1に
        mainCamera.targetDisplay = 0;
    }

    void Update()
    {
        if (Input.GetKeyDown(KeyCode.Tab))
        {
            usingDisplay2 = !usingDisplay2;

            // Display 0 = ディスプレイ1、Display 1 = ディスプレイ2
            mainCamera.targetDisplay = usingDisplay2 ? 1 : 0;
        }
    }
}


