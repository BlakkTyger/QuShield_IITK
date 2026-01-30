interface ScoreGaugeProps {
  score: number;
  maxScore?: number;
  category: string;
  size?: number;
}

export default function ScoreGauge({ score, maxScore = 1000, category, size = 200 }: ScoreGaugeProps) {
  const radius = (size - 20) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(score / maxScore, 1);
  const dashOffset = circumference * (1 - progress);

  const getColor = () => {
    if (score >= 700) return '#22C55E';
    if (score >= 400) return '#F59E0B';
    return '#EF4444';
  };

  const getCategoryClass = () => {
    if (score >= 700) return 'elite';
    if (score >= 400) return 'standard';
    return 'legacy';
  };

  return (
    <div className="score-gauge">
      <div className="gauge-circle" style={{ width: size, height: size }}>
        <svg viewBox={`0 0 ${size} ${size}`}>
          <circle
            className="gauge-bg"
            cx={size / 2}
            cy={size / 2}
            r={radius}
          />
          <circle
            className="gauge-fill"
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={getColor()}
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
          />
        </svg>
        <span className="gauge-score">
          {score}<span className="gauge-max">/{maxScore}</span>
        </span>
      </div>
      <span className={`gauge-label ${getCategoryClass()}`}>
        {category}
      </span>
    </div>
  );
}
