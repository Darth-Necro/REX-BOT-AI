import React from 'react';
import RexGuardDog from '../components/RexGuardDog';
import StatusCards from '../components/StatusCards';
import AlertFeed from '../components/AlertFeed';

export default function BasicView() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[calc(100vh-4rem)] px-4 py-8 gap-8">
      <RexGuardDog />
      <StatusCards />
      <AlertFeed />
    </div>
  );
}
