import React from 'react';

export default function AlphaBanner({ feature }) {
  return (
    <div className="bg-amber-50 border-l-4 border-amber-400 p-3 mb-4 rounded">
      <p className="text-amber-700 text-sm font-medium">
        {feature || 'This feature'} is in alpha and may be incomplete.
      </p>
    </div>
  );
}
