document.addEventListener('DOMContentLoaded', () => {
    const analysisContainer = document.getElementById('analysis-grid');

    if (analysisContainer && typeof analysisData !== 'undefined') {
        if (!analysisData || analysisData.length === 0) {
            analysisContainer.innerHTML = "<p style='color:#94a3b8; text-align:center; padding: 2rem;'>No anomaly logs found in the database.</p>";
            return;
        }

        let html = '';

        analysisData.forEach(item => {
            const isCyber = item.hasOwnProperty('source_ip');

            if (isCyber) {
                const src = item.source_ip || "Unknown";
                const dst = item.dest_ip || "Unknown";
                const protocol = item.protocol || "TCP";
                const attackType = (item.attack_type || "ANOMALY").toUpperCase();
                const score = item.severity_score || 0;
                const time = item.timestamp || "N/A";
                const len = item.packet_length || 0;

                const isCritical = score > 1.5;
                const borderClass = isCritical ? 'critical' : 'warning'; 
                const alertColor = isCritical ? '#ef4444' : '#f59e0b'; 
                const actionText = isCritical ? 'BLOCK IP' : 'FLAGGED';
                const actionBg = isCritical ? '#b91c1c' : '#b45309';

                html += `
                <div class="diagnosis-card" style="border-left: 5px solid ${alertColor}; background: #1e293b; border-radius: 12px; overflow: hidden; margin-bottom: 1.5rem;">
                    <div class="diagnosis-header" style="background: rgba(0,0,0,0.2); padding: 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155;">
                        <span style="font-weight: 700; color: #e2e8f0; font-family: 'Roboto Mono', monospace;">
                            SRC: <span style="color: #3b82f6;">${src}</span> 
                            <span style="color:#64748b; margin: 0 0.5rem;">➔</span> 
                            DST: <span style="color: #3b82f6;">${dst}</span>
                        </span>
                        <span style="color: ${alertColor}; font-weight: 800; font-size: 0.9rem;">⚠ ${attackType}</span>
                    </div>
                    
                    <div class="diagnosis-body" style="padding: 1.5rem; display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
                        <div class="io-section">
                            <h4 style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-top:0; margin-bottom: 0.8rem; letter-spacing: 1px;">Packet Info</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-family: 'Roboto Mono', monospace; font-size: 0.9rem; color: #cbd5e1;">
                                <span>Protocol:</span> <span style="color: white;">${protocol}</span>
                                <span>Size:</span> <span style="color: white;">${len} B</span>
                                <span>Time:</span> <span style="font-size: 0.8rem; color: #94a3b8;">${time}</span>
                            </div>
                        </div>
                        
                        <div class="io-section">
                            <h4 style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-top:0; margin-bottom: 0.8rem; letter-spacing: 1px;">AI Diagnosis</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-family: 'Roboto Mono', monospace; font-size: 0.9rem;">
                                <span style="color: #cbd5e1;">Threat Score:</span> 
                                <span style="color: ${alertColor}; font-weight:bold">${score}</span>
                                
                                <span style="color: #cbd5e1;">Action:</span> 
                                <span><span style="color: white; background: ${actionBg}; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">${actionText}</span></span>
                            </div>
                        </div>
                    </div>
                </div>
                `;

            } else {
                const sensor = item.sensor || item.sensor_id || "N/A";
                const zone = item.zone || item.location || "N/A";
                const alertName = item.alert || "ANOMALY";
                const score = item.severity_score || 0;
                
                const vol = item.voltage || (item.metrics && item.metrics.voltage ? item.metrics.voltage.actual : 0);
                const cur = item.current || (item.metrics && item.metrics.current ? item.metrics.current.actual : 0);
                const pow = item.power    || (item.metrics && item.metrics.power ? item.metrics.power.actual : 0);
                const time = item.timestamp || "N/A";

                const isCritical = score > 1.0;
                const alertColor = isCritical ? '#ef4444' : '#f59e0b'; 

                html += `
                <div class="diagnosis-card" style="border-left: 5px solid ${alertColor}; background: #1e293b; border-radius: 12px; overflow: hidden; margin-bottom: 1.5rem;">
                    <div class="diagnosis-header" style="background: rgba(0,0,0,0.2); padding: 1rem; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155;">
                        <span style="font-weight: 700; color: #e2e8f0;">
                            SENSOR: <span style="color: #3b82f6;">${sensor}</span> | 
                            ZONE: <span style="color: #3b82f6;">${zone}</span>
                        </span>
                        <span style="color: ${alertColor}; font-weight: 800;">${alertName}</span>
                    </div>
                    
                    <div class="diagnosis-body" style="padding: 1.5rem; display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
                        <div class="io-section">
                            <h4 style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-top:0; margin-bottom: 0.8rem; letter-spacing: 1px;">Grid Metrics</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-family: 'Roboto Mono', monospace; font-size: 0.9rem; color: #cbd5e1;">
                                <span>Voltage:</span> <span style="color: white;">${Number(vol).toFixed(2)} V</span>
                                <span>Current:</span> <span style="color: white;">${Number(cur).toFixed(2)} A</span>
                                <span>Power:</span> <span style="color: white;">${Number(pow).toFixed(2)} kW</span>
                                <span>Time:</span> <span style="font-size: 0.8rem; color: #94a3b8;">${time}</span>
                            </div>
                        </div>
                        
                        <div class="io-section">
                            <h4 style="color: #94a3b8; font-size: 0.75rem; text-transform: uppercase; margin-top:0; margin-bottom: 0.8rem; letter-spacing: 1px;">AI Diagnosis</h4>
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-family: 'Roboto Mono', monospace; font-size: 0.9rem;">
                                <span style="color: #cbd5e1;">Severity:</span> 
                                <span style="color: ${alertColor}; font-weight:bold">${score}</span>
                                
                                <span style="color: #cbd5e1;">Status:</span> 
                                <span style="color: white; font-weight: bold;">${isCritical ? 'CRITICAL' : 'MODERATE'}</span>
                            </div>
                        </div>
                    </div>
                </div>
                `;
            }
        });

        analysisContainer.innerHTML = html;
    }
});