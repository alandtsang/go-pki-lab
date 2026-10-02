package platform

type DeploymentReconcileResult struct {
	ScannedTargets int             `json:"scanned_targets"`
	CreatedJobs    []DeploymentJob `json:"created_jobs"`
	ExistingJobs   []DeploymentJob `json:"existing_jobs"`
	SkippedTargets []string        `json:"skipped_targets"`
}

func (s *Service) RunDeploymentReconcile() (DeploymentReconcileResult, error) {
	targets := s.DeploymentTargets("")
	result := DeploymentReconcileResult{ScannedTargets: len(targets)}
	for _, target := range targets {
		if !target.Enabled {
			result.SkippedTargets = append(result.SkippedTargets, target.ID)
			continue
		}
		instance, err := s.DomainCertificateInstance(target.Domain)
		if err != nil {
			return result, err
		}
		if instance.CurrentCertificate == nil {
			result.SkippedTargets = append(result.SkippedTargets, target.ID)
			continue
		}
		job, created, err := s.ensureDeploymentJob(target, instance.CurrentCertificate.SerialNumber)
		if err != nil {
			return result, err
		}
		if created {
			result.CreatedJobs = append(result.CreatedJobs, job)
		} else {
			result.ExistingJobs = append(result.ExistingJobs, job)
		}
	}
	return result, nil
}
