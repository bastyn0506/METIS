using UnityEngine;

public class CircleGrid : MonoBehaviour
{
    public Material lineMaterial;
    public int circleCount = 5;     // “¯S‰~‚Ì”
    public float circleSpacing = 1; // ‰~“¯m‚ÌŠÔŠu
    public int segments = 64;       // 1‰~‚Ìü•ª”
    public int radialLines = 8;     // •úËü‚Ì–{”

    void Start()
    {
        CreateConcentricCircles();
        CreateRadialLines();
    }

    void CreateConcentricCircles()
    {
        for (int i = 1; i <= circleCount; i++)
        {
            float radius = i * circleSpacing;
            GameObject circle = new GameObject($"Circle_{i}");
            circle.transform.parent = this.transform;

            LineRenderer lr = circle.AddComponent<LineRenderer>();
            lr.material = lineMaterial;
            lr.positionCount = segments + 1;
            lr.useWorldSpace = false;
            lr.loop = true;
            lr.widthMultiplier = 0.02f;

            for (int j = 0; j <= segments; j++)
            {
                float angle = j * Mathf.PI * 2 / segments;
                float x = Mathf.Cos(angle) * radius;
                float z = Mathf.Sin(angle) * radius;
                lr.SetPosition(j, new Vector3(x, 0, z));
            }
        }
    }

    void CreateRadialLines()
    {
        for (int i = 0; i < radialLines; i++)
        {
            float angle = i * Mathf.PI * 2 / radialLines;
            float x = Mathf.Cos(angle) * circleCount * circleSpacing;
            float z = Mathf.Sin(angle) * circleCount * circleSpacing;

            GameObject line = new GameObject($"Radial_{i}");
            line.transform.parent = this.transform;

            LineRenderer lr = line.AddComponent<LineRenderer>();
            lr.material = lineMaterial;
            lr.positionCount = 2;
            lr.useWorldSpace = false;
            lr.widthMultiplier = 0.02f;

            lr.SetPosition(0, Vector3.zero);
            lr.SetPosition(1, new Vector3(x, 0, z));
        }
    }
}
