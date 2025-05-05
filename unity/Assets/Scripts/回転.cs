using UnityEngine;

public class Rotator : MonoBehaviour
{
    public Vector3 rotationSpeed = new Vector3(0f, 50f, 0f); // Y軸に回転

    void Update()
    {
        transform.Rotate(rotationSpeed * Time.deltaTime);
    }
}
