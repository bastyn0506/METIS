using UnityEngine;

public class SonarScanRotator : MonoBehaviour
{
    public float rotationSpeed = 30f; // 回転速度（度/秒）

    void Update()
    {
        transform.Rotate(Vector3.up, rotationSpeed * Time.deltaTime);
    }
}

