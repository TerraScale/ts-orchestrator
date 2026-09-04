package engines

import (
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
)

// BudgetTechnicalInputLimits ports the technical caller-input snapshot
// limits; these are not monetary, capacity, or approval policy.
const (
	BudgetTechnicalInputLimitsMaximumEvidenceCount        = 4096
	BudgetTechnicalInputLimitsMaximumNodeClassPolicyCount = 4096
)

// budgetInputSnapshotTryCopy ports the internal BudgetInputSnapshot.TryCopy.
func budgetInputSnapshotTryCopy[T any](source []T, maximum int) ([]T, bool) {
	if source == nil || maximum < 0 || len(source) > maximum {
		return nil, false
	}
	return source, true
}

// budgetIdentityRulesIsValid ports the internal identity rules.
func budgetIdentityRulesIsValid(value string, maximumLength int) bool {
	if maximumLength <= 0 || len(value) == 0 || len(value) > maximumLength {
		return false
	}
	runes := []rune(value)
	for index := 0; index < len(runes); index++ {
		character := runes[index]
		if shared.IsSpaceRune(character) || IsControlRune(character) {
			return false
		}
		if character >= 0xD800 && character <= 0xDBFF {
			if index+1 >= len(runes) || !(runes[index+1] >= 0xDC00 && runes[index+1] <= 0xDFFF) {
				return false
			}
			index++
		} else if character >= 0xDC00 && character <= 0xDFFF {
			return false
		}
	}
	return true
}

func IsControlRune(r rune) bool {
	return (r >= 0x00 && r <= 0x1F) || (r >= 0x7F && r <= 0x9F)
}

// BudgetCellId is a validated cell identity.
type BudgetCellId struct {
	Value string
	valid bool
}

func (i BudgetCellId) IsValid() bool { return i.valid }

func BudgetCellIdTryCreate(value string, maximumLength int) (BudgetCellId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return BudgetCellId{Value: value, valid: true}, true
	}
	return BudgetCellId{}, false
}

// BudgetNodeClassId is a validated node-class identity.
type BudgetNodeClassId struct {
	Value string
	valid bool
}

func (i BudgetNodeClassId) IsValid() bool { return i.valid }

func BudgetNodeClassIdTryCreate(value string, maximumLength int) (BudgetNodeClassId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return BudgetNodeClassId{Value: value, valid: true}, true
	}
	return BudgetNodeClassId{}, false
}

// BudgetCostCenterId is a validated cost-center identity.
type BudgetCostCenterId struct {
	Value string
	valid bool
}

func (i BudgetCostCenterId) IsValid() bool { return i.valid }

func BudgetCostCenterIdTryCreate(value string, maximumLength int) (BudgetCostCenterId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return BudgetCostCenterId{Value: value, valid: true}, true
	}
	return BudgetCostCenterId{}, false
}

// BudgetResourceId is a validated resource identity.
type BudgetResourceId struct {
	Value string
	valid bool
}

func (i BudgetResourceId) IsValid() bool { return i.valid }

func BudgetResourceIdTryCreate(value string, maximumLength int) (BudgetResourceId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return BudgetResourceId{Value: value, valid: true}, true
	}
	return BudgetResourceId{}, false
}

// PriceEvidenceId is a validated price-evidence identity.
type PriceEvidenceId struct {
	Value string
	valid bool
}

func (i PriceEvidenceId) IsValid() bool { return i.valid }

func PriceEvidenceIdTryCreate(value string, maximumLength int) (PriceEvidenceId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return PriceEvidenceId{Value: value, valid: true}, true
	}
	return PriceEvidenceId{}, false
}

// BudgetApprovalId is a validated approval identity.
type BudgetApprovalId struct {
	Value string
	valid bool
}

func (i BudgetApprovalId) IsValid() bool { return i.valid }

func BudgetApprovalIdTryCreate(value string, maximumLength int) (BudgetApprovalId, bool) {
	if budgetIdentityRulesIsValid(value, maximumLength) {
		return BudgetApprovalId{Value: value, valid: true}, true
	}
	return BudgetApprovalId{}, false
}

// BudgetQuantity is a non-negative fixed-point base unit. Unit scale belongs
// to the explicit policy schema.
type BudgetQuantity struct {
	Value int64
}

func (q BudgetQuantity) IsValid() bool { return q.Value >= 0 }

func BudgetQuantityTryCreate(value int64) (BudgetQuantity, bool) {
	if value >= 0 {
		return BudgetQuantity{Value: value}, true
	}
	return BudgetQuantity{}, false
}

// BudgetDimension is the flags vocabulary of budgeted dimensions.
type BudgetDimension int

const (
	BudgetDimensionNone                BudgetDimension = 0
	BudgetDimensionCpu                 BudgetDimension = 1 << 0
	BudgetDimensionMemory              BudgetDimension = 1 << 1
	BudgetDimensionStorage             BudgetDimension = 1 << 2
	BudgetDimensionIops                BudgetDimension = 1 << 3
	BudgetDimensionThroughput          BudgetDimension = 1 << 4
	BudgetDimensionPublicIp            BudgetDimension = 1 << 5
	BudgetDimensionLoadBalancerBackend BudgetDimension = 1 << 6
	BudgetDimensionHourlySpend         BudgetDimension = 1 << 7
	BudgetDimensionDailySpend          BudgetDimension = 1 << 8
	BudgetDimensionAll                 BudgetDimension = BudgetDimensionCpu | BudgetDimensionMemory |
		BudgetDimensionStorage | BudgetDimensionIops | BudgetDimensionThroughput | BudgetDimensionPublicIp |
		BudgetDimensionLoadBalancerBackend | BudgetDimensionHourlySpend | BudgetDimensionDailySpend
)

type BudgetVector struct {
	Cpu                 BudgetQuantity
	Memory              BudgetQuantity
	Storage             BudgetQuantity
	Iops                BudgetQuantity
	Throughput          BudgetQuantity
	PublicIp            BudgetQuantity
	LoadBalancerBackend BudgetQuantity
	HourlySpend         BudgetQuantity
	DailySpend          BudgetQuantity
}

func NewBudgetVector(cpu, memory, storage, iops, throughput, publicIp, loadBalancerBackend,
	hourlySpend, dailySpend BudgetQuantity) BudgetVector {
	return BudgetVector{cpu, memory, storage, iops, throughput, publicIp, loadBalancerBackend,
		hourlySpend, dailySpend}
}

func (v BudgetVector) IsValid() bool {
	return v.Cpu.IsValid() && v.Memory.IsValid() && v.Storage.IsValid() && v.Iops.IsValid() &&
		v.Throughput.IsValid() && v.PublicIp.IsValid() && v.LoadBalancerBackend.IsValid() &&
		v.HourlySpend.IsValid() && v.DailySpend.IsValid()
}

// BudgetVectorZero mirrors BudgetVector.Zero.
var BudgetVectorZero = BudgetVector{}

func (v BudgetVector) values() [9]int64 {
	return [9]int64{v.Cpu.Value, v.Memory.Value, v.Storage.Value, v.Iops.Value, v.Throughput.Value,
		v.PublicIp.Value, v.LoadBalancerBackend.Value, v.HourlySpend.Value, v.DailySpend.Value}
}

func budgetVectorFrom(values [9]int64) BudgetVector {
	return BudgetVector{
		Cpu: BudgetQuantity{values[0]}, Memory: BudgetQuantity{values[1]}, Storage: BudgetQuantity{values[2]},
		Iops: BudgetQuantity{values[3]}, Throughput: BudgetQuantity{values[4]}, PublicIp: BudgetQuantity{values[5]},
		LoadBalancerBackend: BudgetQuantity{values[6]}, HourlySpend: BudgetQuantity{values[7]},
		DailySpend: BudgetQuantity{values[8]},
	}
}

func (v BudgetVector) TryAdd(other BudgetVector) (BudgetVector, bool) {
	return v.tryCombine(other, true)
}

func (v BudgetVector) TrySubtract(other BudgetVector) (BudgetVector, bool) {
	return v.tryCombine(other, false)
}

func (v BudgetVector) tryCombine(other BudgetVector, add bool) (BudgetVector, bool) {
	left := v.values()
	right := other.values()
	var values [9]int64
	for index := 0; index < 9; index++ {
		sum, ok := shared.CheckedAddInt64(left[index], right[index])
		if add {
			if !ok {
				return BudgetVector{}, false
			}
			values[index] = sum
		} else {
			difference := left[index] - right[index]
			if (right[index] > 0 && difference > left[index]) || (right[index] < 0 && difference < left[index]) {
				return BudgetVector{}, false
			}
			values[index] = difference
		}
		if values[index] < 0 {
			return BudgetVector{}, false
		}
	}
	return budgetVectorFrom(values), true
}

func (v BudgetVector) ExceededBy(maximum BudgetVector) BudgetDimension {
	dimensions := BudgetDimensionNone
	if v.Cpu.Value > maximum.Cpu.Value {
		dimensions |= BudgetDimensionCpu
	}
	if v.Memory.Value > maximum.Memory.Value {
		dimensions |= BudgetDimensionMemory
	}
	if v.Storage.Value > maximum.Storage.Value {
		dimensions |= BudgetDimensionStorage
	}
	if v.Iops.Value > maximum.Iops.Value {
		dimensions |= BudgetDimensionIops
	}
	if v.Throughput.Value > maximum.Throughput.Value {
		dimensions |= BudgetDimensionThroughput
	}
	if v.PublicIp.Value > maximum.PublicIp.Value {
		dimensions |= BudgetDimensionPublicIp
	}
	if v.LoadBalancerBackend.Value > maximum.LoadBalancerBackend.Value {
		dimensions |= BudgetDimensionLoadBalancerBackend
	}
	if v.HourlySpend.Value > maximum.HourlySpend.Value {
		dimensions |= BudgetDimensionHourlySpend
	}
	if v.DailySpend.Value > maximum.DailySpend.Value {
		dimensions |= BudgetDimensionDailySpend
	}
	return dimensions
}

func (v BudgetVector) IsStorageSafetyDomainIncrease() bool {
	return v.Storage.Value > 0 && v.Cpu.Value == 0 && v.Memory.Value == 0 &&
		v.PublicIp.Value == 0 && v.LoadBalancerBackend.Value == 0
}

func (v BudgetVector) Equal(other BudgetVector) bool {
	return v.values() == other.values()
}

func (v BudgetVector) String() string {
	return "cpu=" + shared.ItoaCompact(v.Cpu.Value) + ";memory=" + shared.ItoaCompact(v.Memory.Value) +
		";storage=" + shared.ItoaCompact(v.Storage.Value) + ";iops=" + shared.ItoaCompact(v.Iops.Value) +
		";throughput=" + shared.ItoaCompact(v.Throughput.Value) + ";publicIp=" + shared.ItoaCompact(v.PublicIp.Value) +
		";lbBackend=" + shared.ItoaCompact(v.LoadBalancerBackend.Value) + ";hourly=" + shared.ItoaCompact(v.HourlySpend.Value) +
		";daily=" + shared.ItoaCompact(v.DailySpend.Value)
}
